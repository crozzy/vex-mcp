package vex

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quay/claircore/toolkit/types/csaf"
)

// VEXClient handles interactions with Red Hat VEX data
type VEXClient struct {
	VEXBaseURL  string
	CSAFBaseURL string
	Client      *http.Client
}

// NewVEXClient creates a new VEX client with improved HTTP configuration
func NewVEXClient() *VEXClient {
	return &VEXClient{
		VEXBaseURL:  "https://access.redhat.com/security/data/csaf/v2/vex",
		CSAFBaseURL: "https://security.access.redhat.com/data/csaf/v2/advisories",
		Client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     60 * time.Second,
				DisableKeepAlives:   false,
			},
		},
	}
}

// validateCVEYear validates the year component of a CVE ID
func validateCVEYear(year string) error {
	if len(year) != 4 {
		return fmt.Errorf("CVE year must be 4 digits, got %d", len(year))
	}

	yearInt, err := strconv.Atoi(year)
	if err != nil {
		return fmt.Errorf("CVE year must be numeric: %s", year)
	}

	if yearInt < 1999 || yearInt > time.Now().Year()+1 {
		return fmt.Errorf("CVE year %d outside valid range (1999-%d)", yearInt, time.Now().Year()+1)
	}

	return nil
}

// validateRHSAYear validates the year component of an RHSA ID
func validateRHSAYear(year string) error {
	if len(year) != 4 {
		return fmt.Errorf("RHSA year must be 4 digits, got %d", len(year))
	}

	yearInt, err := strconv.Atoi(year)
	if err != nil {
		return fmt.Errorf("RHSA year must be numeric: %s", year)
	}

	if yearInt < 2000 || yearInt > time.Now().Year()+1 {
		return fmt.Errorf("RHSA year %d outside valid range (2000-%d)", yearInt, time.Now().Year()+1)
	}

	return nil
}

// GetVEXDocument retrieves a VEX document for a specific CVE with context support
func (c *VEXClient) GetVEXDocument(cveID string) (*csaf.CSAF, error) {
	return c.GetVEXDocumentWithContext(context.Background(), cveID)
}

// GetVEXDocumentWithContext retrieves a VEX document for a specific CVE with context support
func (c *VEXClient) GetVEXDocumentWithContext(ctx context.Context, cveID string) (*csaf.CSAF, error) {
	// Validate CVE ID format
	if !strings.HasPrefix(strings.ToUpper(cveID), "CVE-") {
		return nil, fmt.Errorf("invalid CVE ID format: %s (must start with CVE-)", cveID)
	}

	// Normalize CVE ID to uppercase
	cveID = strings.ToUpper(cveID)

	// Extract year from CVE ID for URL construction
	parts := strings.Split(cveID, "-")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("invalid CVE ID format: %s (must be CVE-YYYY-NNNN)", cveID)
	}
	year := parts[1]
	sequence := parts[2]

	// Validate year
	if err := validateCVEYear(year); err != nil {
		return nil, fmt.Errorf("invalid CVE ID: %w", err)
	}

	// Validate sequence number is not empty and is numeric
	if sequence == "" {
		return nil, fmt.Errorf("invalid CVE ID format: %s (sequence number cannot be empty)", cveID)
	}
	if _, err := strconv.Atoi(sequence); err != nil {
		return nil, fmt.Errorf("invalid CVE ID format: %s (sequence number must be numeric)", cveID)
	}

	// Construct URL: https://access.redhat.com/security/data/csaf/v2/vex/2024/cve-2024-1234.json
	url := fmt.Sprintf("%s/%s/%s.json", c.VEXBaseURL, year, strings.ToLower(cveID))

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Make HTTP request
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch VEX document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("VEX document not found for CVE %s", cveID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d when fetching VEX document for %s", resp.StatusCode, cveID)
	}

	// Read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var csafDoc csaf.CSAF
	if err := json.Unmarshal(body, &csafDoc); err != nil {
		return nil, fmt.Errorf("failed to parse VEX document: %w", err)
	}

	return &csafDoc, nil
}

// GetRHSADocument retrieves a CSAF document for a specific RHSA with context support
func (c *VEXClient) GetRHSADocument(rhsaID string) (*csaf.CSAF, error) {
	return c.GetRHSADocumentWithContext(context.Background(), rhsaID)
}

// GetRHSADocumentWithContext retrieves a CSAF document for a specific RHSA with context support
func (c *VEXClient) GetRHSADocumentWithContext(ctx context.Context, rhsaID string) (*csaf.CSAF, error) {
	// Validate RHSA ID format (e.g., RHSA-2024:1234)
	if !strings.HasPrefix(strings.ToUpper(rhsaID), "RHSA-") {
		return nil, fmt.Errorf("invalid RHSA ID format: %s (must start with RHSA-)", rhsaID)
	}

	// Normalize RHSA ID to uppercase
	rhsaID = strings.ToUpper(rhsaID)

	// Extract year from RHSA ID for URL construction
	parts := strings.Split(rhsaID, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid RHSA ID format: %s (must be RHSA-YYYY:NNNN)", rhsaID)
	}

	// Split the second part by colon to get year and number
	yearAndNum := strings.Split(parts[1], ":")
	if len(yearAndNum) != 2 || yearAndNum[0] == "" || yearAndNum[1] == "" {
		return nil, fmt.Errorf("invalid RHSA ID format: %s (must be RHSA-YYYY:NNNN)", rhsaID)
	}
	year := yearAndNum[0]
	sequence := yearAndNum[1]

	// Validate year
	if err := validateRHSAYear(year); err != nil {
		return nil, fmt.Errorf("invalid RHSA ID: %w", err)
	}

	// Validate sequence number is numeric
	if _, err := strconv.Atoi(sequence); err != nil {
		return nil, fmt.Errorf("invalid RHSA ID format: %s (sequence number must be numeric)", rhsaID)
	}

	// Construct URL: https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_1234.json
	// Convert RHSA-2024:1234 to rhsa-2024_1234
	fileName := strings.ToLower(strings.Replace(rhsaID, ":", "_", -1))
	url := fmt.Sprintf("%s/%s/%s.json", c.CSAFBaseURL, year, fileName)

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Make HTTP request
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RHSA document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("RHSA document not found for %s", rhsaID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d when fetching RHSA document for %s", resp.StatusCode, rhsaID)
	}

	// Read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var csafDoc csaf.CSAF
	if err := json.Unmarshal(body, &csafDoc); err != nil {
		return nil, fmt.Errorf("failed to parse RHSA document: %w", err)
	}

	return &csafDoc, nil
}

// IsPackageAffectedByCVE checks if a specific package is affected by a CVE
func IsPackageAffectedByCVE(doc *csaf.CSAF, packageName string) (bool, string, []string) {
	matchingProducts := []string{}

	for _, vuln := range doc.Vulnerabilities {
		// Check in known affected products
		if knownAffected, exists := vuln.ProductStatus["known_affected"]; exists {
			for _, productID := range knownAffected {
				if strings.Contains(strings.ToLower(productID), strings.ToLower(packageName)) {
					matchingProducts = append(matchingProducts, productID)
				}
			}
		}

		// Check in fixed products (they were affected but now fixed)
		if fixed, exists := vuln.ProductStatus["fixed"]; exists {
			for _, productID := range fixed {
				if strings.Contains(strings.ToLower(productID), strings.ToLower(packageName)) {
					matchingProducts = append(matchingProducts, productID)
				}
			}
		}
	}

	if len(matchingProducts) > 0 {
		return true, "Package is affected by this CVE", matchingProducts
	}

	// Check if explicitly marked as not affected
	for _, vuln := range doc.Vulnerabilities {
		if knownNotAffected, exists := vuln.ProductStatus["known_not_affected"]; exists {
			for _, productID := range knownNotAffected {
				if strings.Contains(strings.ToLower(productID), strings.ToLower(packageName)) {
					return false, "Package is explicitly marked as not affected", []string{productID}
				}
			}
		}
	}

	return false, "Package not found in VEX document", []string{}
}

// IsPackageFixedByRHSA checks if a specific package is fixed by an RHSA
func IsPackageFixedByRHSA(doc *csaf.CSAF, packageName string) (bool, string, []string) {
	matchingProducts := []string{}

	for _, vuln := range doc.Vulnerabilities {
		// Check in fixed products
		if fixed, exists := vuln.ProductStatus["fixed"]; exists {
			for _, productID := range fixed {
				if strings.Contains(strings.ToLower(productID), strings.ToLower(packageName)) {
					matchingProducts = append(matchingProducts, productID)
				}
			}
		}
	}

	if len(matchingProducts) > 0 {
		return true, "Package is fixed by this RHSA", matchingProducts
	}

	// Check if package is mentioned but not fixed
	for _, vuln := range doc.Vulnerabilities {
		allProducts := []string{}
		if knownAffected, exists := vuln.ProductStatus["known_affected"]; exists {
			allProducts = append(allProducts, knownAffected...)
		}
		if underInvestigation, exists := vuln.ProductStatus["under_investigation"]; exists {
			allProducts = append(allProducts, underInvestigation...)
		}
		if knownNotAffected, exists := vuln.ProductStatus["known_not_affected"]; exists {
			allProducts = append(allProducts, knownNotAffected...)
		}

		for _, productID := range allProducts {
			if strings.Contains(strings.ToLower(productID), strings.ToLower(packageName)) {
				return false, "Package found but not fixed by this RHSA", []string{productID}
			}
		}
	}

	return false, "Package not found in RHSA document", []string{}
}

// GetPackagesByDocument returns all packages affected by this CSAF document
func GetPackagesByDocument(doc *csaf.CSAF) map[string][]string {
	result := make(map[string][]string)

	for _, vuln := range doc.Vulnerabilities {
		if knownAffected, exists := vuln.ProductStatus["known_affected"]; exists {
			result["affected"] = append(result["affected"], knownAffected...)
		}

		if fixed, exists := vuln.ProductStatus["fixed"]; exists {
			result["fixed"] = append(result["fixed"], fixed...)
		}

		if knownNotAffected, exists := vuln.ProductStatus["known_not_affected"]; exists {
			result["not_affected"] = append(result["not_affected"], knownNotAffected...)
		}

		if underInvestigation, exists := vuln.ProductStatus["under_investigation"]; exists {
			result["under_investigation"] = append(result["under_investigation"], underInvestigation...)
		}
	}

	return result
}

// GetVulnerabilityStats returns a summary of the vulnerability status
func GetVulnerabilityStats(doc *csaf.CSAF) map[string]int {
	status := make(map[string]int)

	for _, vuln := range doc.Vulnerabilities {
		if fixed, exists := vuln.ProductStatus["fixed"]; exists {
			status["fixed"] += len(fixed)
		}
		if knownAffected, exists := vuln.ProductStatus["known_affected"]; exists {
			status["known_affected"] += len(knownAffected)
		}
		if knownNotAffected, exists := vuln.ProductStatus["known_not_affected"]; exists {
			status["known_not_affected"] += len(knownNotAffected)
		}
		if underInvestigation, exists := vuln.ProductStatus["under_investigation"]; exists {
			status["under_investigation"] += len(underInvestigation)
		}
	}

	return status
}

// GetAffectedProducts returns a list of products affected by the vulnerability
func GetAffectedProducts(doc *csaf.CSAF) []string {
	products := make([]string, 0)

	for _, vuln := range doc.Vulnerabilities {
		if knownAffected, exists := vuln.ProductStatus["known_affected"]; exists {
			products = append(products, knownAffected...)
		}
		if fixed, exists := vuln.ProductStatus["fixed"]; exists {
			products = append(products, fixed...)
		}
	}

	return products
}

// GetSeverity returns the aggregate severity of the vulnerability
func GetSeverity(doc *csaf.CSAF) string {
	// Check vulnerabilities for severity information
	for _, vuln := range doc.Vulnerabilities {
		for _, threat := range vuln.Threats {
			if threat.Category == "impact" {
				return threat.Details
			}
		}
	}
	return "unknown"
}

// FormatSummary returns a human-readable summary of the CSAF document
func FormatSummary(doc *csaf.CSAF) string {
	status := GetVulnerabilityStats(doc)
	severity := GetSeverity(doc)

	summary := fmt.Sprintf("Document: %s\n", doc.Document.Tracking.ID)
	if doc.Document.Title != "" {
		summary += fmt.Sprintf("Title: %s\n", doc.Document.Title)
	}
	summary += fmt.Sprintf("Severity: %s\n", severity)
	if !doc.Document.Tracking.CurrentReleaseDate.IsZero() {
		summary += fmt.Sprintf("Last Updated: %s\n", doc.Document.Tracking.CurrentReleaseDate.Format("2006-01-02"))
	}
	summary += "\nProduct Status:\n"

	if status["fixed"] > 0 {
		summary += fmt.Sprintf("  • Fixed: %d products\n", status["fixed"])
	}
	if status["known_affected"] > 0 {
		summary += fmt.Sprintf("  • Known Affected: %d products\n", status["known_affected"])
	}
	if status["known_not_affected"] > 0 {
		summary += fmt.Sprintf("  • Not Affected: %d products\n", status["known_not_affected"])
	}
	if status["under_investigation"] > 0 {
		summary += fmt.Sprintf("  • Under Investigation: %d products\n", status["under_investigation"])
	}

	// Add VEX source citation
	summary += "\n" + FormatVEXCitation(doc)

	return summary
}

// FormatRHSASummary returns a human-readable summary of the RHSA CSAF document
func FormatRHSASummary(doc *csaf.CSAF) string {
	status := GetVulnerabilityStats(doc)
	severity := GetSeverity(doc)

	summary := fmt.Sprintf("Document: %s\n", doc.Document.Tracking.ID)
	if doc.Document.Title != "" {
		summary += fmt.Sprintf("Title: %s\n", doc.Document.Title)
	}
	summary += fmt.Sprintf("Severity: %s\n", severity)
	if !doc.Document.Tracking.CurrentReleaseDate.IsZero() {
		summary += fmt.Sprintf("Last Updated: %s\n", doc.Document.Tracking.CurrentReleaseDate.Format("2006-01-02"))
	}
	summary += "\nProduct Status:\n"

	if status["fixed"] > 0 {
		summary += fmt.Sprintf("  • Fixed: %d products\n", status["fixed"])
	}
	if status["known_affected"] > 0 {
		summary += fmt.Sprintf("  • Known Affected: %d products\n", status["known_affected"])
	}
	if status["known_not_affected"] > 0 {
		summary += fmt.Sprintf("  • Not Affected: %d products\n", status["known_not_affected"])
	}
	if status["under_investigation"] > 0 {
		summary += fmt.Sprintf("  • Under Investigation: %d products\n", status["under_investigation"])
	}

	// Add RHSA source citation
	summary += "\n" + FormatRHSACitation(doc)

	return summary
}

// FormatVEXCitation returns a properly formatted citation for the VEX document
func FormatVEXCitation(doc *csaf.CSAF) string {
	citation := "📄 **VEX Source Citation:**\n"
	citation += fmt.Sprintf("**Red Hat VEX Document**: `%s`\n", doc.Document.Tracking.ID)

	if doc.Document.Title != "" {
		citation += fmt.Sprintf("**Title**: \"%s\"\n", doc.Document.Title)
	}

	if !doc.Document.Tracking.CurrentReleaseDate.IsZero() {
		citation += fmt.Sprintf("**Last Updated**: %s\n", doc.Document.Tracking.CurrentReleaseDate.Format("2006-01-02"))
	}

	// Generate the URL based on document ID
	citation += fmt.Sprintf("**URL**: `%s`", GenerateVEXURL(doc.Document.Tracking.ID))

	return citation
}

// FormatRHSACitation returns a properly formatted citation for the RHSA document
func FormatRHSACitation(doc *csaf.CSAF) string {
	citation := "📄 **RHSA Source Citation:**\n"
	citation += fmt.Sprintf("**Red Hat Security Advisory**: `%s`\n", doc.Document.Tracking.ID)

	if doc.Document.Title != "" {
		citation += fmt.Sprintf("**Title**: \"%s\"\n", doc.Document.Title)
	}

	if !doc.Document.Tracking.CurrentReleaseDate.IsZero() {
		citation += fmt.Sprintf("**Last Updated**: %s\n", doc.Document.Tracking.CurrentReleaseDate.Format("2006-01-02"))
	}

	// Generate the URL based on document ID
	citation += fmt.Sprintf("**URL**: `%s`", GenerateRHSAURL(doc.Document.Tracking.ID))

	return citation
}

// GenerateVEXURL creates the VEX document URL from a CVE ID
func GenerateVEXURL(cveID string) string {
	if !strings.HasPrefix(strings.ToUpper(cveID), "CVE-") {
		return ""
	}

	// Extract year from CVE ID
	parts := strings.Split(strings.ToUpper(cveID), "-")
	if len(parts) != 3 {
		return ""
	}
	year := parts[1]

	return fmt.Sprintf("https://access.redhat.com/security/data/csaf/v2/vex/%s/%s.json",
		year, strings.ToLower(cveID))
}

// GenerateRHSAURL creates the RHSA document URL from an RHSA ID
func GenerateRHSAURL(rhsaID string) string {
	if !strings.HasPrefix(strings.ToUpper(rhsaID), "RHSA-") {
		return ""
	}

	// Extract year from RHSA ID
	parts := strings.Split(strings.ToUpper(rhsaID), "-")
	if len(parts) != 2 {
		return ""
	}

	yearAndNum := strings.Split(parts[1], ":")
	if len(yearAndNum) != 2 {
		return ""
	}
	year := yearAndNum[0]

	// Convert RHSA-2024:1234 to rhsa-2024_1234
	fileName := strings.ToLower(strings.Replace(rhsaID, ":", "_", -1))

	return fmt.Sprintf("https://security.access.redhat.com/data/csaf/v2/advisories/%s/%s.json",
		year, fileName)
}

// ProductIdentification represents the identification information for a product
type ProductIdentification struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
	CPE       string `json:"cpe,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

// ProductTreeMapping represents the mapping of products to their identifications
type ProductTreeMapping struct {
	Products      map[string]*ProductIdentification `json:"products"`
	Relationships map[string]*ProductRelationship   `json:"relationships"`
}

// ProductRelationship represents a relationship between products
type ProductRelationship struct {
	ProductID        string                 `json:"product_id"`
	Name             string                 `json:"name"`
	Category         string                 `json:"category"`
	ProductReference string                 `json:"product_reference"`
	RelatesTo        string                 `json:"relates_to"`
	BaseProduct      *ProductIdentification `json:"base_product,omitempty"`
	ComponentProduct *ProductIdentification `json:"component_product,omitempty"`
}

// ExtractProductTreeMapping extracts all product identification information from a CSAF document
func ExtractProductTreeMapping(doc *csaf.CSAF) *ProductTreeMapping {
	mapping := &ProductTreeMapping{
		Products:      make(map[string]*ProductIdentification),
		Relationships: make(map[string]*ProductRelationship),
	}

	// Extract products from branches
	extractProductsFromBranches(doc.ProductTree.Branches, mapping.Products)

	// Extract relationships
	extractProductRelationships(doc.ProductTree.Relationships, mapping)

	return mapping
}

// extractProductsFromBranches recursively extracts products from branches
func extractProductsFromBranches(branches []csaf.ProductBranch, products map[string]*ProductIdentification) {
	for _, branch := range branches {
		// Check if this branch has a product (check if ID is not empty)
		if branch.Product.ID != "" {
			product := &ProductIdentification{
				ProductID: branch.Product.ID,
				Name:      branch.Product.Name,
			}

			// Extract CPE/PURL from product identification helper
			if branch.Product.IdentificationHelper != nil {
				if cpe, exists := branch.Product.IdentificationHelper["cpe"]; exists {
					product.CPE = cpe
				}
				if purl, exists := branch.Product.IdentificationHelper["purl"]; exists {
					product.PURL = purl
				}
			}

			if product.ProductID != "" {
				products[product.ProductID] = product
			}
		}

		// Recursively process sub-branches
		extractProductsFromBranches(branch.Branches, products)
	}
}

// extractProductRelationships extracts product relationships
func extractProductRelationships(relationships csaf.Relationships, mapping *ProductTreeMapping) {
	for _, rel := range relationships {
		relationship := &ProductRelationship{
			ProductID:        rel.FullProductName.ID,
			Name:             rel.FullProductName.Name,
			Category:         rel.Category,
			ProductReference: rel.ProductRef,
			RelatesTo:        rel.RelatesToProductRef,
		}

		// Resolve component and base products
		if relationship.ProductReference != "" {
			relationship.ComponentProduct = mapping.Products[relationship.ProductReference]
		}
		if relationship.RelatesTo != "" {
			relationship.BaseProduct = mapping.Products[relationship.RelatesTo]
		}

		if relationship.ProductID != "" {
			mapping.Relationships[relationship.ProductID] = relationship
		}
	}
}

// ResolveProductIdentifiers resolves a list of product IDs to their underlying identifications
func ResolveProductIdentifiers(doc *csaf.CSAF, productIDs []string) map[string]*ProductResolution {
	mapping := ExtractProductTreeMapping(doc)
	resolutions := make(map[string]*ProductResolution)

	for _, productID := range productIDs {
		resolutions[productID] = ResolveProductIdentifier(mapping, productID)
	}

	return resolutions
}

// ProductResolution contains the resolved identification for a product
type ProductResolution struct {
	ProductID        string                 `json:"product_id"`
	Name             string                 `json:"name"`
	Type             string                 `json:"type"` // "base", "component", "composite"
	CPE              string                 `json:"cpe,omitempty"`
	PURL             string                 `json:"purl,omitempty"`
	BaseProduct      *ProductIdentification `json:"base_product,omitempty"`
	ComponentProduct *ProductIdentification `json:"component_product,omitempty"`
	Relationship     *ProductRelationship   `json:"relationship,omitempty"`
}

// ResolveProductIdentifier resolves a single product ID to its underlying identification
func ResolveProductIdentifier(mapping *ProductTreeMapping, productID string) *ProductResolution {
	resolution := &ProductResolution{
		ProductID: productID,
	}

	// Check if it's a direct product
	if product, exists := mapping.Products[productID]; exists {
		resolution.Name = product.Name
		resolution.CPE = product.CPE
		resolution.PURL = product.PURL
		resolution.Type = "base"
		if product.PURL != "" {
			resolution.Type = "component"
		}
		return resolution
	}

	// Check if it's a relationship (composite product)
	if relationship, exists := mapping.Relationships[productID]; exists {
		resolution.Name = relationship.Name
		resolution.Type = "composite"
		resolution.Relationship = relationship
		resolution.BaseProduct = relationship.BaseProduct
		resolution.ComponentProduct = relationship.ComponentProduct
		return resolution
	}

	// Unknown product
	resolution.Type = "unknown"
	return resolution
}

// GetProductCPEs returns CPE identifiers for a list of product IDs
func GetProductCPEs(doc *csaf.CSAF, productIDs []string) []string {
	resolutions := ResolveProductIdentifiers(doc, productIDs)
	var cpes []string

	for _, resolution := range resolutions {
		if resolution.CPE != "" {
			cpes = append(cpes, resolution.CPE)
		}
		if resolution.BaseProduct != nil && resolution.BaseProduct.CPE != "" {
			cpes = append(cpes, resolution.BaseProduct.CPE)
		}
	}

	return cpes
}

// GetProductPURLs returns PURL identifiers for a list of product IDs
func GetProductPURLs(doc *csaf.CSAF, productIDs []string) []string {
	resolutions := ResolveProductIdentifiers(doc, productIDs)
	var purls []string

	for _, resolution := range resolutions {
		if resolution.PURL != "" {
			purls = append(purls, resolution.PURL)
		}
		if resolution.ComponentProduct != nil && resolution.ComponentProduct.PURL != "" {
			purls = append(purls, resolution.ComponentProduct.PURL)
		}
	}

	return purls
}

// FormatProductResolutions formats product resolutions for display
func FormatProductResolutions(resolutions map[string]*ProductResolution) string {
	if len(resolutions) == 0 {
		return "No product resolutions found."
	}

	result := "🔍 **Product Identity Resolution:**\n\n"

	for productID, resolution := range resolutions {
		result += fmt.Sprintf("**Product ID**: `%s`\n", productID)
		result += fmt.Sprintf("**Name**: %s\n", resolution.Name)
		result += fmt.Sprintf("**Type**: %s\n", resolution.Type)

		if resolution.CPE != "" {
			result += fmt.Sprintf("**CPE**: `%s`\n", resolution.CPE)
		}
		if resolution.PURL != "" {
			result += fmt.Sprintf("**PURL**: `%s`\n", resolution.PURL)
		}

		if resolution.Type == "composite" && resolution.Relationship != nil {
			result += fmt.Sprintf("**Relationship**: %s\n", resolution.Relationship.Category)

			if resolution.BaseProduct != nil {
				result += fmt.Sprintf("**Base OS**: %s", resolution.BaseProduct.Name)
				if resolution.BaseProduct.CPE != "" {
					result += fmt.Sprintf(" (`%s`)", resolution.BaseProduct.CPE)
				}
				result += "\n"
			}

			if resolution.ComponentProduct != nil {
				result += fmt.Sprintf("**Component**: %s", resolution.ComponentProduct.Name)
				if resolution.ComponentProduct.PURL != "" {
					result += fmt.Sprintf(" (`%s`)", resolution.ComponentProduct.PURL)
				}
				result += "\n"
			}
		}

		result += "\n"
	}

	return result
}
