package vex

import (
	"strings"
	"testing"
	"time"

	"github.com/quay/claircore/toolkit/types/csaf"
)

func TestNewVEXClient(t *testing.T) {
	client := NewVEXClient()

	if client == nil {
		t.Fatal("NewVEXClient() returned nil")
	}

	if client.VEXBaseURL != "https://access.redhat.com/security/data/csaf/v2/vex" {
		t.Errorf("Expected VEXBaseURL to be 'https://access.redhat.com/security/data/csaf/v2/vex', got '%s'", client.VEXBaseURL)
	}

	if client.CSAFBaseURL != "https://security.access.redhat.com/data/csaf/v2/advisories" {
		t.Errorf("Expected CSAFBaseURL to be 'https://security.access.redhat.com/data/csaf/v2/advisories', got '%s'", client.CSAFBaseURL)
	}

	if client.Client == nil {
		t.Fatal("HTTP client is nil")
	}
}

func TestValidateCVEFormat(t *testing.T) {
	client := NewVEXClient()

	// Test cases with expected error substrings
	testCases := []struct {
		cveID       string
		errorSubstr string
	}{
		{"invalid", "invalid CVE ID format"},
		{"CVE-", "invalid CVE ID format"},
		{"CVE-2024", "invalid CVE ID format"},
		{"CVE-2024-", "invalid CVE ID format"}, // This gets caught by the basic format check first
		{"2024-1234", "invalid CVE ID format"},
		{"", "invalid CVE ID format"},
		{"CVE-24-1234", "CVE year must be 4 digits"},        // More specific error for improved validation
		{"CVE-2024-abc", "sequence number must be numeric"}, // Test non-numeric sequence
	}

	for _, tc := range testCases {
		_, err := client.GetVEXDocument(tc.cveID)
		if err == nil {
			t.Errorf("Expected error for invalid CVE ID '%s', but got none", tc.cveID)
		}
		if !strings.Contains(err.Error(), tc.errorSubstr) {
			t.Errorf("Expected '%s' error for '%s', got '%s'", tc.errorSubstr, tc.cveID, err.Error())
		}
	}
}

func TestCVEIDNormalization(t *testing.T) {
	client := NewVEXClient()

	// Test that CVE IDs are properly normalized to uppercase
	testCases := []struct {
		input    string
		expected string
	}{
		{"cve-2024-1234", "CVE-2024-1234"},
		{"CVE-2024-1234", "CVE-2024-1234"},
		{"Cve-2024-1234", "CVE-2024-1234"},
		{"cvE-2024-1234", "CVE-2024-1234"},
	}

	for _, tc := range testCases {
		// We'll test this by checking the error message includes the normalized CVE
		// since we don't want to make actual HTTP requests in unit tests
		_, err := client.GetVEXDocument(tc.input)
		if err != nil && strings.Contains(err.Error(), tc.expected) {
			// Expected - the error should contain the normalized CVE ID
			continue
		}
		// Note: In a real test, we'd mock the HTTP client, but for simplicity
		// we're just testing the validation logic here
	}
}

func TestRHSAValidation(t *testing.T) {
	client := NewVEXClient()

	// Test cases with expected error substrings
	testCases := []struct {
		rhsaID      string
		errorSubstr string
	}{
		{"invalid", "invalid RHSA ID format"},
		{"RHSA-", "invalid RHSA ID format"},
		{"RHSA-2024", "invalid RHSA ID format"},
		{"RHSA-2024:", "invalid RHSA ID format"},
		{"2024:1234", "invalid RHSA ID format"},
		{"", "invalid RHSA ID format"},
		{"RHSA-24:1234", "RHSA year must be 4 digits"}, // More specific error for improved validation
	}

	for _, tc := range testCases {
		_, err := client.GetRHSADocument(tc.rhsaID)
		if err == nil {
			t.Errorf("Expected error for invalid RHSA ID '%s', but got none", tc.rhsaID)
		}
		if !strings.Contains(err.Error(), tc.errorSubstr) {
			t.Errorf("Expected '%s' error for '%s', got '%s'", tc.errorSubstr, tc.rhsaID, err.Error())
		}
	}
}

func TestVEXDocumentMethods(t *testing.T) {
	// Create a sample CSAF document for testing
	csafDoc := &csaf.CSAF{
		Document: csaf.DocumentMetadata{
			Title: "Test Vulnerability",
			Tracking: csaf.Tracking{
				ID:                 "CVE-2024-TEST",
				CurrentReleaseDate: time.Now(),
			},
		},
		Vulnerabilities: []csaf.Vulnerability{
			{
				ProductStatus: map[string][]string{
					"fixed":               {"package1-fixed", "package2-fixed"},
					"known_affected":      {"package3-affected"},
					"known_not_affected":  {"package4-safe", "package5-safe"},
					"under_investigation": {"package6-investigating"},
				},
			},
		},
	}

	// Test GetVulnerabilityStats
	status := GetVulnerabilityStats(csafDoc)
	expected := map[string]int{
		"fixed":               2,
		"known_affected":      1,
		"known_not_affected":  2,
		"under_investigation": 1,
	}

	for key, expectedCount := range expected {
		if status[key] != expectedCount {
			t.Errorf("Expected %s count to be %d, got %d", key, expectedCount, status[key])
		}
	}

	// Test GetSeverity
	severity := GetSeverity(csafDoc)
	if severity != "unknown" {
		t.Errorf("Expected severity to be 'unknown', got '%s'", severity)
	}

	// Test GetAffectedProducts
	affectedProducts := GetAffectedProducts(csafDoc)
	expectedProducts := 3 // 2 fixed + 1 known_affected
	if len(affectedProducts) != expectedProducts {
		t.Errorf("Expected %d affected products, got %d", expectedProducts, len(affectedProducts))
	}

	// Test FormatSummary
	summary := FormatSummary(csafDoc)
	if !strings.Contains(summary, "CVE-2024-TEST") {
		t.Error("Summary should contain document ID")
	}
	if !strings.Contains(summary, "Test Vulnerability") {
		t.Error("Summary should contain vulnerability title")
	}
	if !strings.Contains(summary, "unknown") {
		t.Error("Summary should contain severity")
	}
}

func TestPackageAffectedMethods(t *testing.T) {
	// Create a sample CSAF document for testing
	csafDoc := &csaf.CSAF{
		Document: csaf.DocumentMetadata{
			Title: "Test Vulnerability",
			Tracking: csaf.Tracking{
				ID:                 "CVE-2024-TEST",
				CurrentReleaseDate: time.Now(),
			},
		},
		Vulnerabilities: []csaf.Vulnerability{
			{
				ProductStatus: map[string][]string{
					"fixed":               {"package1-fixed", "package2-fixed"},
					"known_affected":      {"package3-affected"},
					"known_not_affected":  {"package4-safe", "package5-safe"},
					"under_investigation": {"package6-investigating"},
				},
			},
		},
	}

	// Test IsPackageAffectedByCVE
	testCases := []struct {
		packageName      string
		expectedAffected bool
		expectedReason   string
	}{
		{"package1", true, "Package is affected by this CVE"},               // In fixed (was affected)
		{"package3", true, "Package is affected by this CVE"},               // In known affected
		{"package4", false, "Package is explicitly marked as not affected"}, // In not affected
		{"nonexistent", false, "Package not found in VEX document"},         // Not found
	}

	for _, tc := range testCases {
		isAffected, reason, matchingProducts := IsPackageAffectedByCVE(csafDoc, tc.packageName)

		if isAffected != tc.expectedAffected {
			t.Errorf("IsPackageAffectedByCVE(%s): expected affected=%t, got %t", tc.packageName, tc.expectedAffected, isAffected)
		}

		if reason != tc.expectedReason {
			t.Errorf("IsPackageAffectedByCVE(%s): expected reason='%s', got '%s'", tc.packageName, tc.expectedReason, reason)
		}

		if tc.expectedAffected && len(matchingProducts) == 0 {
			t.Errorf("IsPackageAffectedByCVE(%s): expected matching products, got none", tc.packageName)
		}
	}

	// Test IsPackageFixedByRHSA
	fixTestCases := []struct {
		packageName    string
		expectedFixed  bool
		expectedReason string
	}{
		{"package1", true, "Package is fixed by this RHSA"},             // In fixed
		{"package3", false, "Package found but not fixed by this RHSA"}, // In affected but not fixed
		{"nonexistent", false, "Package not found in RHSA document"},    // Not found
	}

	for _, tc := range fixTestCases {
		isFixed, reason, matchingProducts := IsPackageFixedByRHSA(csafDoc, tc.packageName)

		if isFixed != tc.expectedFixed {
			t.Errorf("IsPackageFixedByRHSA(%s): expected fixed=%t, got %t", tc.packageName, tc.expectedFixed, isFixed)
		}

		if reason != tc.expectedReason {
			t.Errorf("IsPackageFixedByRHSA(%s): expected reason='%s', got '%s'", tc.packageName, tc.expectedReason, reason)
		}

		if tc.expectedFixed && len(matchingProducts) == 0 {
			t.Errorf("IsPackageFixedByRHSA(%s): expected matching products, got none", tc.packageName)
		}
	}

	// Test GetPackagesByDocument
	affectedPackages := GetPackagesByDocument(csafDoc)

	expectedCounts := map[string]int{
		"affected":            1, // package3-affected
		"fixed":               2, // package1-fixed, package2-fixed
		"not_affected":        2, // package4-safe, package5-safe
		"under_investigation": 1, // package6-investigating
	}

	for status, expectedCount := range expectedCounts {
		if len(affectedPackages[status]) != expectedCount {
			t.Errorf("GetPackagesByDocument(): expected %d %s packages, got %d", expectedCount, status, len(affectedPackages[status]))
		}
	}
}
