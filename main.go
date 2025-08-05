package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	mcp "github.com/metoro-io/mcp-golang"
	"github.com/metoro-io/mcp-golang/transport/stdio"
	"github.com/quay/claircore/toolkit/types/csaf"
	"github.com/ryanuber/go-filecache"

	"github.com/crozzy/vex-mcp/vex"
)

// Configuration constants
const (
	DefaultCacheTime = 300 * time.Second // 5 minutes cache time for VEX documents
	DefaultPageLimit = 50
	MaxPageLimit     = 500
	HTTPTimeout      = 30 * time.Second
	MaxCacheSize     = 100 * 1024 * 1024 // 100MB
)

var logger *slog.Logger

type CVELookupArgs struct {
	CVE string `json:"cve" jsonschema:"required,description=The CVE ID to look up (e.g., CVE-2024-1234)"`
}

type RHSALookupArgs struct {
	RHSA string `json:"rhsa" jsonschema:"required,description=The RHSA ID to look up (e.g., RHSA-2024:1234)"`
}

type PackageAffectedByCVEArgs struct {
	CVE     string `json:"cve" jsonschema:"required,description=The CVE ID to check"`
	Package string `json:"package" jsonschema:"required,description=The package name to check if affected"`
	Limit   *int   `json:"limit,omitempty" jsonschema:"description=Maximum number of matching products to return (default: 50)"`
	Offset  *int   `json:"offset,omitempty" jsonschema:"description=Number of matching products to skip (default: 0)"`
}

type PackageFixedByRHSAArgs struct {
	RHSA    string `json:"rhsa" jsonschema:"required,description=The RHSA ID to check"`
	Package string `json:"package" jsonschema:"required,description=The package name to check if fixed"`
	Limit   *int   `json:"limit,omitempty" jsonschema:"description=Maximum number of matching products to return (default: 50)"`
	Offset  *int   `json:"offset,omitempty" jsonschema:"description=Number of matching products to skip (default: 0)"`
}

type AffectedPackagesArgs struct {
	ID     string `json:"id" jsonschema:"required,description=The CVE or RHSA ID to list affected packages for"`
	Limit  *int   `json:"limit,omitempty" jsonschema:"description=Maximum number of packages to return per status category (default: 50)"`
	Offset *int   `json:"offset,omitempty" jsonschema:"description=Number of packages to skip per status category (default: 0)"`
}

type ResolveProductIdentifiersArgs struct {
	ID         string   `json:"id" jsonschema:"required,description=The CVE or RHSA ID to resolve products for"`
	ProductIDs []string `json:"product_ids,omitempty" jsonschema:"description=Optional list of specific product IDs to resolve (if empty, resolves all not-affected products)"`
}

type PackageVulnerabilityStatusArgs struct {
	ID      string `json:"id" jsonschema:"required,description=The CVE or RHSA ID to check"`
	Package string `json:"package" jsonschema:"required,description=The package name to filter vulnerability status for"`
	Limit   *int   `json:"limit,omitempty" jsonschema:"description=Maximum number of packages to return per status category (default: 50)"`
	Offset  *int   `json:"offset,omitempty" jsonschema:"description=Number of packages to skip per status category (default: 0)"`
}

// Helper function to apply pagination to a slice
func paginateSlice(items []string, limit, offset *int) ([]string, bool, int) {
	actualLimit := DefaultPageLimit
	if limit != nil && *limit > 0 && *limit <= MaxPageLimit { // Cap at 500 to prevent huge responses
		actualLimit = *limit
	}

	actualOffset := 0
	if offset != nil && *offset >= 0 {
		actualOffset = *offset
	}

	totalItems := len(items)

	// Check if offset is beyond available items
	if actualOffset >= totalItems {
		return []string{}, false, totalItems
	}

	// Calculate end index
	end := actualOffset + actualLimit
	if end > totalItems {
		end = totalItems
	}

	// Determine if there are more items available
	hasMore := end < totalItems

	return items[actualOffset:end], hasMore, totalItems
}

// Helper function to format pagination info
func formatPaginationInfo(limit, offset *int, totalItems int, hasMore bool) string {
	actualLimit := DefaultPageLimit
	if limit != nil {
		actualLimit = *limit
	}

	actualOffset := 0
	if offset != nil {
		actualOffset = *offset
	}

	info := fmt.Sprintf("\n📄 Pagination: Showing %d-%d of %d total items",
		actualOffset+1,
		min(actualOffset+actualLimit, totalItems),
		totalItems)

	if hasMore {
		nextOffset := actualOffset + actualLimit
		info += fmt.Sprintf("\n   Next page: offset=%d, limit=%d", nextOffset, actualLimit)
	}

	return info
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getDocumentByID fetches a CSAF document by ID (CVE or RHSA)
func getDocumentByID(id string) (*csaf.CSAF, string, error) {
	upperID := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(upperID, "CVE-"):
		doc, err := getVEXDocument(id)
		return doc, "CVE", err
	case strings.HasPrefix(upperID, "RHSA-"):
		doc, err := getRHSADocument(id)
		return doc, "RHSA", err
	default:
		return nil, "", fmt.Errorf("invalid ID format: %s (must be CVE-YYYY-NNNN or RHSA-YYYY:NNNN)", id)
	}
}

func main() {
	// Initialize structured logger
	logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	logger.Info("Starting VEX MCP Server")

	done := make(chan struct{})
	server := mcp.NewServer(stdio.NewStdioServerTransport())

	// Register CVE lookup tool
	err := server.RegisterTool("lookup_cve", "Look up detailed Red Hat VEX document information for a CVE ID", func(args CVELookupArgs) (*mcp.ToolResponse, error) {
		logger.Debug("CVE lookup requested", "cve", args.CVE)

		vexDoc, err := getVEXDocument(args.CVE)
		if err != nil {
			logger.Error("Failed to get VEX document", "cve", args.CVE, "error", err)
			return nil, err
		}

		response := fmt.Sprintf("Red Hat VEX Document for %s\n\n", args.CVE)
		response += vex.FormatSummary(vexDoc)

		// Add remediation information if available
		if len(vexDoc.Vulnerabilities) > 0 && len(vexDoc.Vulnerabilities[0].Remediations) > 0 {
			response += "\nRemediation Information:\n"
			for _, remediation := range vexDoc.Vulnerabilities[0].Remediations {
				if remediation.URL != "" {
					response += fmt.Sprintf("  • %s: %s\n", remediation.Category, remediation.URL)
				}
				if remediation.Details != "" {
					response += fmt.Sprintf("    Details: %s\n", remediation.Details)
				}
			}
		}

		logger.Debug("CVE lookup completed", "cve", args.CVE)
		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		logger.Error("Failed to register CVE lookup tool", "error", err)
		os.Exit(1)
	}

	// Register RHSA lookup tool
	err = server.RegisterTool("lookup_rhsa", "Look up detailed Red Hat CSAF advisory information for an RHSA ID", func(args RHSALookupArgs) (*mcp.ToolResponse, error) {
		logger.Debug("RHSA lookup requested", "rhsa", args.RHSA)

		rhsaDoc, err := getRHSADocument(args.RHSA)
		if err != nil {
			logger.Error("Failed to get RHSA document", "rhsa", args.RHSA, "error", err)
			return nil, err
		}

		response := fmt.Sprintf("Red Hat Security Advisory %s\n\n", args.RHSA)
		response += vex.FormatRHSASummary(rhsaDoc)

		// Add remediation information if available
		if len(rhsaDoc.Vulnerabilities) > 0 && len(rhsaDoc.Vulnerabilities[0].Remediations) > 0 {
			response += "\nRemediation Information:\n"
			for _, remediation := range rhsaDoc.Vulnerabilities[0].Remediations {
				if remediation.URL != "" {
					response += fmt.Sprintf("  • %s: %s\n", remediation.Category, remediation.URL)
				}
				if remediation.Details != "" {
					response += fmt.Sprintf("    Details: %s\n", remediation.Details)
				}
			}
		}

		logger.Debug("RHSA lookup completed", "rhsa", args.RHSA)
		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		logger.Error("Failed to register RHSA lookup tool", "error", err)
		os.Exit(1)
	}

	// Register package affected by CVE check tool
	err = server.RegisterTool("is_package_affected_by_cve", "Check if a specific package is affected by a CVE. Supports pagination for large result sets (default: limit=50, offset=0, max=500).", func(args PackageAffectedByCVEArgs) (*mcp.ToolResponse, error) {
		logger.Debug("Package affected by CVE check requested", "cve", args.CVE, "package", args.Package)

		vexDoc, err := getVEXDocument(args.CVE)
		if err != nil {
			logger.Error("Failed to get VEX document for package check", "cve", args.CVE, "error", err)
			return nil, err
		}

		isAffected, status, matchingProducts := vex.IsPackageAffectedByCVE(vexDoc, args.Package)

		response := fmt.Sprintf("Package Status Check: %s in %s\n\n", args.Package, args.CVE)
		response += fmt.Sprintf("Result: %s\n", status)
		response += fmt.Sprintf("Affected: %t\n\n", isAffected)

		if len(matchingProducts) > 0 {
			// Apply pagination to matching products
			paginatedProducts, hasMore, totalCount := paginateSlice(matchingProducts, args.Limit, args.Offset)

			response += "Matching Products:\n"
			for _, product := range paginatedProducts {
				response += fmt.Sprintf("  • %s\n", product)
			}

			// Add pagination info if we're not showing all items
			if totalCount > len(paginatedProducts) || hasMore {
				response += formatPaginationInfo(args.Limit, args.Offset, totalCount, hasMore)
			}
		}

		// Add VEX source citation
		response += "\n" + vex.FormatVEXCitation(vexDoc)

		logger.Debug("Package affected by CVE check completed", "cve", args.CVE, "package", args.Package)
		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		logger.Error("Failed to register package affected by CVE tool", "error", err)
		os.Exit(1)
	}

	// Register package fixed by RHSA check tool
	err = server.RegisterTool("is_package_fixed_by_rhsa", "Check if a specific package is fixed by an RHSA. Supports pagination for large result sets (default: limit=50, offset=0, max=500).", func(args PackageFixedByRHSAArgs) (*mcp.ToolResponse, error) {
		logger.Debug("Package fixed by RHSA check requested", "rhsa", args.RHSA, "package", args.Package)

		rhsaDoc, err := getRHSADocument(args.RHSA)
		if err != nil {
			logger.Error("Failed to get RHSA document for package check", "rhsa", args.RHSA, "error", err)
			return nil, err
		}

		isFixed, status, matchingProducts := vex.IsPackageFixedByRHSA(rhsaDoc, args.Package)

		response := fmt.Sprintf("Package Fix Status Check: %s in %s\n\n", args.Package, args.RHSA)
		response += fmt.Sprintf("Result: %s\n", status)
		response += fmt.Sprintf("Fixed: %t\n\n", isFixed)

		if len(matchingProducts) > 0 {
			// Apply pagination to matching products
			paginatedProducts, hasMore, totalCount := paginateSlice(matchingProducts, args.Limit, args.Offset)

			response += "Matching Products:\n"
			for _, product := range paginatedProducts {
				response += fmt.Sprintf("  • %s\n", product)
			}

			// Add pagination info if we're not showing all items
			if totalCount > len(paginatedProducts) || hasMore {
				response += formatPaginationInfo(args.Limit, args.Offset, totalCount, hasMore)
			}
		}

		// Add RHSA source citation
		response += "\n" + vex.FormatRHSACitation(rhsaDoc)

		logger.Debug("Package fixed by RHSA check completed", "rhsa", args.RHSA, "package", args.Package)
		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		logger.Error("Failed to register package fixed by RHSA tool", "error", err)
		os.Exit(1)
	}

	// Register affected packages listing tool
	err = server.RegisterTool("list_affected_packages", "List all packages affected by a CVE or RHSA. Supports pagination per status category (default: limit=50, offset=0, max=500).", func(args AffectedPackagesArgs) (*mcp.ToolResponse, error) {
		logger.Debug("List affected packages requested", "id", args.ID)

		doc, docType, err := getDocumentByID(args.ID)
		if err != nil {
			logger.Error("Failed to get document for list_affected_packages", "id", args.ID, "error", err)
			return nil, err
		}

		affectedPackages := vex.GetPackagesByDocument(doc)

		response := fmt.Sprintf("Packages Affected by %s %s\n\n", docType, args.ID)

		// Track pagination info across categories
		var totalDisplayed, totalAvailable int
		var hasMoreAny bool

		if packages, exists := affectedPackages["affected"]; exists && len(packages) > 0 {
			paginatedPackages, hasMore, totalCount := paginateSlice(packages, args.Limit, args.Offset)
			response += "⚠️  AFFECTED Packages:\n"
			for _, pkg := range paginatedPackages {
				response += fmt.Sprintf("  • %s\n", pkg)
			}
			if totalCount > len(paginatedPackages) || hasMore {
				response += formatPaginationInfo(args.Limit, args.Offset, totalCount, hasMore) + "\n"
				hasMoreAny = hasMoreAny || hasMore
			}
			response += "\n"
			totalDisplayed += len(paginatedPackages)
			totalAvailable += totalCount
		}

		if packages, exists := affectedPackages["fixed"]; exists && len(packages) > 0 {
			paginatedPackages, hasMore, totalCount := paginateSlice(packages, args.Limit, args.Offset)
			response += "✅ FIXED Packages:\n"
			for _, pkg := range paginatedPackages {
				response += fmt.Sprintf("  • %s\n", pkg)
			}
			if totalCount > len(paginatedPackages) || hasMore {
				response += formatPaginationInfo(args.Limit, args.Offset, totalCount, hasMore) + "\n"
				hasMoreAny = hasMoreAny || hasMore
			}
			response += "\n"
			totalDisplayed += len(paginatedPackages)
			totalAvailable += totalCount
		}

		if packages, exists := affectedPackages["not_affected"]; exists && len(packages) > 0 {
			paginatedPackages, hasMore, totalCount := paginateSlice(packages, args.Limit, args.Offset)
			response += "✅ NOT AFFECTED Packages:\n"
			for _, pkg := range paginatedPackages {
				response += fmt.Sprintf("  • %s\n", pkg)
			}
			if totalCount > len(paginatedPackages) || hasMore {
				response += formatPaginationInfo(args.Limit, args.Offset, totalCount, hasMore) + "\n"
				hasMoreAny = hasMoreAny || hasMore
			}
			response += "\n"
			totalDisplayed += len(paginatedPackages)
			totalAvailable += totalCount
		}

		if packages, exists := affectedPackages["under_investigation"]; exists && len(packages) > 0 {
			paginatedPackages, hasMore, totalCount := paginateSlice(packages, args.Limit, args.Offset)
			response += "🔍 UNDER INVESTIGATION Packages:\n"
			for _, pkg := range paginatedPackages {
				response += fmt.Sprintf("  • %s\n", pkg)
			}
			if totalCount > len(paginatedPackages) || hasMore {
				response += formatPaginationInfo(args.Limit, args.Offset, totalCount, hasMore) + "\n"
				hasMoreAny = hasMoreAny || hasMore
			}
			response += "\n"
			totalDisplayed += len(paginatedPackages)
			totalAvailable += totalCount
		}

		// Summary
		totalAffected := len(affectedPackages["affected"]) + len(affectedPackages["fixed"])
		totalNotAffected := len(affectedPackages["not_affected"])
		totalInvestigation := len(affectedPackages["under_investigation"])

		response += "Summary:\n"
		response += fmt.Sprintf("  • Total Affected/Fixed: %d\n", totalAffected)
		response += fmt.Sprintf("  • Total Not Affected: %d\n", totalNotAffected)
		response += fmt.Sprintf("  • Total Under Investigation: %d\n", totalInvestigation)

		// Add appropriate source citation based on document type
		if docType == "CVE" {
			response += "\n" + vex.FormatVEXCitation(doc)
		} else {
			response += "\n" + vex.FormatRHSACitation(doc)
		}

		logger.Debug("List affected packages completed", "id", args.ID)
		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		logger.Error("Failed to register list_affected_packages tool", "error", err)
		os.Exit(1)
	}

	// Register product identifier resolution tool
	err = server.RegisterTool("resolve_product_identifiers", "Resolve VEX/RHSA product identifiers to their underlying CPE and PURL identifiers. Supports both individual CVE/RHSA IDs and specific product ID lists.", func(args ResolveProductIdentifiersArgs) (*mcp.ToolResponse, error) {
		logger.Debug("Product identifier resolution requested", "id", args.ID)

		doc, docType, err := getDocumentByID(args.ID)
		if err != nil {
			logger.Error("Failed to get document for resolve_product_identifiers", "id", args.ID, "error", err)
			return nil, err
		}

		var productIDsToResolve []string

		// If specific product IDs provided, use those
		if len(args.ProductIDs) > 0 {
			productIDsToResolve = args.ProductIDs
		} else {
			// Otherwise, get not-affected products for this document
			affectedPackages := vex.GetPackagesByDocument(doc)
			if notAffected, exists := affectedPackages["not_affected"]; exists {
				productIDsToResolve = notAffected
			}
		}

		if len(productIDsToResolve) == 0 {
			logger.Debug("No products to resolve for resolve_product_identifiers", "id", args.ID)
			return mcp.NewToolResponse(mcp.NewTextContent(fmt.Sprintf("No products to resolve for %s %s", docType, args.ID))), nil
		}

		// Resolve the product identifiers
		resolutions := vex.ResolveProductIdentifiers(doc, productIDsToResolve)

		response := fmt.Sprintf("Product Identifier Resolution for %s %s\n\n", docType, args.ID)
		response += vex.FormatProductResolutions(resolutions)

		// Add CPE and PURL summaries
		cpes := vex.GetProductCPEs(doc, productIDsToResolve)
		purls := vex.GetProductPURLs(doc, productIDsToResolve)

		if len(cpes) > 0 {
			response += "📋 **Summary - CPE Identifiers:**\n"
			for _, cpe := range cpes {
				response += fmt.Sprintf("  • `%s`\n", cpe)
			}
			response += "\n"
		}

		if len(purls) > 0 {
			response += "📦 **Summary - PURL Identifiers:**\n"
			for _, purl := range purls {
				response += fmt.Sprintf("  • `%s`\n", purl)
			}
			response += "\n"
		}

		// Add appropriate source citation
		if docType == "CVE" {
			response += "\n" + vex.FormatVEXCitation(doc)
		} else {
			response += "\n" + vex.FormatRHSACitation(doc)
		}

		logger.Debug("Product identifier resolution completed", "id", args.ID)
		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		logger.Error("Failed to register resolve_product_identifiers tool", "error", err)
		os.Exit(1)
	}

	// Register package vulnerability status tool
	err = server.RegisterTool("get_package_vulnerability_status", "Get comprehensive vulnerability status for a specific package across all categories (vulnerable, fixed, not_affected, etc.) for a CVE or RHSA. Supports pagination per status category.", func(args PackageVulnerabilityStatusArgs) (*mcp.ToolResponse, error) {
		logger.Debug("Package vulnerability status requested", "id", args.ID, "package", args.Package)

		doc, docType, err := getDocumentByID(args.ID)
		if err != nil {
			logger.Error("Failed to get document for get_package_vulnerability_status", "id", args.ID, "error", err)
			return nil, err
		}

		// Get all product IDs categorized by status
		affectedPackages := vex.GetPackagesByDocument(doc)

		response := fmt.Sprintf("Vulnerability Status for Package '%s' in %s %s\n\n", args.Package, docType, args.ID)

		totalPackageCount := 0
		foundStatuses := []string{}

		// Pre-compute lowercase package name for efficient matching
		packageLower := strings.ToLower(args.Package)

		// Check each vulnerability status for the specific package
		for status, products := range affectedPackages {
			if len(products) == 0 {
				continue
			}

			// Get PURLs for this status to filter by package
			allPurls := vex.GetProductPURLs(doc, products)

			// Filter for the specific package
			var packagePurls []string
			for _, purl := range allPurls {
				if strings.Contains(strings.ToLower(purl), packageLower) {
					packagePurls = append(packagePurls, purl)
				}
			}

			if len(packagePurls) > 0 {
				foundStatuses = append(foundStatuses, status)
				totalPackageCount += len(packagePurls)

				// Apply pagination to this status category
				paginatedPurls, hasMore, totalInCategory := paginateSlice(packagePurls, args.Limit, args.Offset)

				response += fmt.Sprintf("## %s (%d packages)\n", strings.ToUpper(status), totalInCategory)

				for _, purl := range paginatedPurls {
					response += fmt.Sprintf("  • `%s`\n", purl)
				}

				// Add pagination info if needed
				if totalInCategory > len(paginatedPurls) || hasMore {
					response += formatPaginationInfo(args.Limit, args.Offset, totalInCategory, hasMore)
				}
				response += "\n"
			}
		}

		if totalPackageCount == 0 {
			response += fmt.Sprintf("❌ **No packages found matching '%s' in %s %s**\n", args.Package, docType, args.ID)
		} else {
			response += fmt.Sprintf("📊 **Summary**: Found %d total %s packages across %d status categories: %s\n",
				totalPackageCount, args.Package, len(foundStatuses), strings.Join(foundStatuses, ", "))
		}

		// Add appropriate source citation
		if docType == "CVE" {
			response += "\n" + vex.FormatVEXCitation(doc)
		} else {
			response += "\n" + vex.FormatRHSACitation(doc)
		}

		logger.Debug("Package vulnerability status completed", "id", args.ID, "package", args.Package)
		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		logger.Error("Failed to register get_package_vulnerability_status tool", "error", err)
		os.Exit(1)
	}

	err = server.Serve()
	if err != nil {
		logger.Error("Server failed to serve", "error", err)
		os.Exit(1)
	}

	<-done
}

func getVEXDocument(cveID string) (*csaf.CSAF, error) {
	// Check cache first
	cached := getFromCache("vex_" + cveID)
	if cached != "" {
		var vexDoc csaf.CSAF
		err := json.Unmarshal([]byte(cached), &vexDoc)
		if err == nil {
			return &vexDoc, nil
		}
	}

	// Fetch from Red Hat VEX API
	client := vex.NewVEXClient()
	vexDoc, err := client.GetVEXDocument(cveID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch VEX document for %s: %w", cveID, err)
	}

	// Cache the result
	docJSON, err := json.Marshal(vexDoc)
	if err == nil {
		saveToCache("vex_"+cveID, string(docJSON))
	}

	return vexDoc, nil
}

func getRHSADocument(rhsaID string) (*csaf.CSAF, error) {
	// Check cache first
	cached := getFromCache("rhsa_" + rhsaID)
	if cached != "" {
		var rhsaDoc csaf.CSAF
		err := json.Unmarshal([]byte(cached), &rhsaDoc)
		if err == nil {
			return &rhsaDoc, nil
		}
	}

	// Fetch from Red Hat RHSA API
	client := vex.NewVEXClient()
	rhsaDoc, err := client.GetRHSADocument(rhsaID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RHSA document for %s: %w", rhsaID, err)
	}

	// Cache the result
	docJSON, err := json.Marshal(rhsaDoc)
	if err == nil {
		saveToCache("rhsa_"+rhsaID, string(docJSON))
	}

	return rhsaDoc, nil
}

func getCacheDir() (string, error) {
	cacheDir := filepath.Join(os.TempDir(), "vex-mcp-cache")
	err := os.MkdirAll(cacheDir, 0700) // Only user can access
	if err != nil {
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}
	return cacheDir, nil
}

func getCacheFilename(key string) (string, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return "", err
	}
	// Sanitize key to prevent path traversal
	safeKey := strings.ReplaceAll(key, "/", "_")
	safeKey = strings.ReplaceAll(safeKey, "\\", "_")
	safeKey = strings.ReplaceAll(safeKey, "..", "_")
	return filepath.Join(cacheDir, safeKey+".cache"), nil
}

func getFromCache(key string) string {
	cacheFile, err := getCacheFilename(key)
	if err != nil {
		logger.Error("Failed to get cache filename", "key", key, "error", err)
		return ""
	}

	updater := func(path string) error {
		return errors.New("expired")
	}

	fc := filecache.New(cacheFile, DefaultCacheTime, updater)

	fh, err := fc.Get()
	if err != nil {
		return ""
	}

	content, err := io.ReadAll(fh)
	if err != nil {
		return ""
	}

	return string(content)
}

func saveToCache(key string, content string) string {
	cacheFile, err := getCacheFilename(key)
	if err != nil {
		logger.Error("Failed to get cache filename for save", "key", key, "error", err)
		return ""
	}

	// Check cache size before saving
	if len(content) > MaxCacheSize {
		logger.Warn("Content too large for cache", "key", key, "size", len(content))
		return ""
	}

	updater := func(path string) error {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write([]byte(content))
		return err
	}

	fc := filecache.New(cacheFile, DefaultCacheTime, updater)

	_, err = fc.Get()
	if err != nil {
		logger.Error("Failed to save to cache", "key", key, "error", err)
		return ""
	}

	return content
}
