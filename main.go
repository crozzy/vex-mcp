package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	mcp "github.com/metoro-io/mcp-golang"
	"github.com/metoro-io/mcp-golang/transport/stdio"
	"github.com/quay/claircore/toolkit/types/csaf"
	"github.com/ryanuber/go-filecache"

	"github.com/crozzy/vex-mcp/vex"
)

const cacheTime = 300 // 5 minutes cache time for VEX documents

type CVELookupArgs struct {
	CVE string `json:"cve" jsonschema:"required,description=The CVE ID to look up (e.g., CVE-2024-1234)"`
}

type RHSALookupArgs struct {
	RHSA string `json:"rhsa" jsonschema:"required,description=The RHSA ID to look up (e.g., RHSA-2024:1234)"`
}

type PackageAffectedByCVEArgs struct {
	CVE     string `json:"cve" jsonschema:"required,description=The CVE ID to check"`
	Package string `json:"package" jsonschema:"required,description=The package name to check if affected"`
}

type PackageFixedByRHSAArgs struct {
	RHSA    string `json:"rhsa" jsonschema:"required,description=The RHSA ID to check"`
	Package string `json:"package" jsonschema:"required,description=The package name to check if fixed"`
}

type AffectedPackagesArgs struct {
	ID string `json:"id" jsonschema:"required,description=The CVE or RHSA ID to list affected packages for"`
}

func main() {
	done := make(chan struct{})

	server := mcp.NewServer(stdio.NewStdioServerTransport())

	// Register CVE lookup tool
	err := server.RegisterTool("lookup_cve", "Look up detailed Red Hat VEX document information for a CVE ID", func(args CVELookupArgs) (*mcp.ToolResponse, error) {
		vexDoc, err := getVEXDocument(args.CVE)
		if err != nil {
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

		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		panic(err)
	}

	// Register RHSA lookup tool
	err = server.RegisterTool("lookup_rhsa", "Look up detailed Red Hat CSAF advisory information for an RHSA ID", func(args RHSALookupArgs) (*mcp.ToolResponse, error) {
		rhsaDoc, err := getRHSADocument(args.RHSA)
		if err != nil {
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

		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		panic(err)
	}

	// Register package affected by CVE check tool
	err = server.RegisterTool("is_package_affected_by_cve", "Check if a specific package is affected by a CVE", func(args PackageAffectedByCVEArgs) (*mcp.ToolResponse, error) {
		vexDoc, err := getVEXDocument(args.CVE)
		if err != nil {
			return nil, err
		}

		isAffected, status, matchingProducts := vex.IsPackageAffectedByCVE(vexDoc, args.Package)

		response := fmt.Sprintf("Package Status Check: %s in %s\n\n", args.Package, args.CVE)
		response += fmt.Sprintf("Result: %s\n", status)
		response += fmt.Sprintf("Affected: %t\n\n", isAffected)

		if len(matchingProducts) > 0 {
			response += "Matching Products:\n"
			for _, product := range matchingProducts {
				response += fmt.Sprintf("  • %s\n", product)
			}
		}

		// Add VEX source citation
		response += "\n" + vex.FormatVEXCitation(vexDoc)

		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		panic(err)
	}

	// Register package fixed by RHSA check tool
	err = server.RegisterTool("is_package_fixed_by_rhsa", "Check if a specific package is fixed by an RHSA", func(args PackageFixedByRHSAArgs) (*mcp.ToolResponse, error) {
		rhsaDoc, err := getRHSADocument(args.RHSA)
		if err != nil {
			return nil, err
		}

		isFixed, status, matchingProducts := vex.IsPackageFixedByRHSA(rhsaDoc, args.Package)

		response := fmt.Sprintf("Package Fix Status Check: %s in %s\n\n", args.Package, args.RHSA)
		response += fmt.Sprintf("Result: %s\n", status)
		response += fmt.Sprintf("Fixed: %t\n\n", isFixed)

		if len(matchingProducts) > 0 {
			response += "Matching Products:\n"
			for _, product := range matchingProducts {
				response += fmt.Sprintf("  • %s\n", product)
			}
		}

		// Add RHSA source citation
		response += "\n" + vex.FormatRHSACitation(rhsaDoc)

		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		panic(err)
	}

	// Register affected packages listing tool
	err = server.RegisterTool("list_affected_packages", "List all packages affected by a CVE or RHSA", func(args AffectedPackagesArgs) (*mcp.ToolResponse, error) {
		var doc *csaf.CSAF
		var err error
		var docType string

		// Determine if it's a CVE or RHSA and get the appropriate document
		if strings.HasPrefix(strings.ToUpper(args.ID), "CVE-") {
			doc, err = getVEXDocument(args.ID)
			docType = "CVE"
		} else if strings.HasPrefix(strings.ToUpper(args.ID), "RHSA-") {
			doc, err = getRHSADocument(args.ID)
			docType = "RHSA"
		} else {
			return nil, fmt.Errorf("invalid ID format: %s (must be CVE-YYYY-NNNN or RHSA-YYYY:NNNN)", args.ID)
		}

		if err != nil {
			return nil, err
		}

		affectedPackages := vex.GetAffectedPackagesByDocument(doc)

		response := fmt.Sprintf("Packages Affected by %s %s\n\n", docType, args.ID)

		if packages, exists := affectedPackages["affected"]; exists && len(packages) > 0 {
			response += "⚠️  AFFECTED Packages:\n"
			for _, pkg := range packages {
				response += fmt.Sprintf("  • %s\n", pkg)
			}
			response += "\n"
		}

		if packages, exists := affectedPackages["fixed"]; exists && len(packages) > 0 {
			response += "✅ FIXED Packages:\n"
			for _, pkg := range packages {
				response += fmt.Sprintf("  • %s\n", pkg)
			}
			response += "\n"
		}

		if packages, exists := affectedPackages["not_affected"]; exists && len(packages) > 0 {
			response += "✅ NOT AFFECTED Packages:\n"
			for _, pkg := range packages {
				response += fmt.Sprintf("  • %s\n", pkg)
			}
			response += "\n"
		}

		if packages, exists := affectedPackages["under_investigation"]; exists && len(packages) > 0 {
			response += "🔍 UNDER INVESTIGATION Packages:\n"
			for _, pkg := range packages {
				response += fmt.Sprintf("  • %s\n", pkg)
			}
			response += "\n"
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

		return mcp.NewToolResponse(mcp.NewTextContent(response)), nil
	})
	if err != nil {
		panic(err)
	}

	err = server.Serve()
	if err != nil {
		panic(err)
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

func getFromCache(key string) string {
	updater := func(path string) error {
		return errors.New("expired")
	}

	fc := filecache.New(getCacheFilename(key), cacheTime*time.Second, updater)

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
	updater := func(path string) error {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write([]byte(content))
		return err
	}

	fc := filecache.New(getCacheFilename(key), cacheTime*time.Second, updater)

	_, err := fc.Get()
	if err != nil {
		return ""
	}

	return content
}

func getCacheFilename(key string) string {
	return os.TempDir() + "/" + strings.Replace(key, "-", "_", -1) + ".cache"
}
