# Red Hat VEX MCP Server

An MCP (Model Context Protocol) server for looking up Red Hat VEX (Vulnerability Exploitability eXchange) documents and security advisories.

## Overview

This MCP server provides tools to query Red Hat's CSAF/VEX documents to answer security-related questions about CVEs and RHSAs. It supports the specific use cases outlined in the requirements:

**Supported Questions:**
- ✅ Is package123 affected by CVE-123?
- ✅ Is package456 fixed with RHSA-456?
- ✅ Which packages are affected by CVE-123/RHSA-456?

**Not Supported (by design):**
- ❌ Which CVEs is package123 affected by?
- ❌ Which RHSA fixed package456's vulnerabilities?

## Features

- **CVE Lookup**: Retrieve detailed VEX documents for specific CVE IDs
- **RHSA Lookup**: Retrieve CSAF advisory documents for specific RHSA IDs
- **Package Status Checking**: Check if packages are affected by specific CVEs
- **Package Fix Status**: Check if packages are fixed by specific RHSAs
- **Affected Package Listing**: List all packages affected by a CVE or RHSA
- **Product Identifier Resolution**: Resolve VEX/RHSA product identifiers to underlying CPE and PURL identifiers
- **Package Vulnerability Status**: Get comprehensive vulnerability status for specific packages across all categories
- **Pagination**: Handle large result sets with configurable pagination (default: 50 items, max: 500)
- **Automatic Citations**: All responses include VEX/RHSA source citations with URLs
- **Caching**: Built-in caching to improve performance and reduce API calls

## Data Sources

- **VEX Documents**: https://access.redhat.com/security/data/csaf/v2/vex/
- **CSAF Advisories**: https://security.access.redhat.com/data/csaf/v2/advisories/

## Installation

```bash
# Clone the repository
git clone https://github.com/crozzy/vex-mcp.git
cd vex-mcp

# Build the server
go build -o vex-mcp-server .
```

## Dependencies

- Claircore CSAF types (`github.com/quay/claircore/toolkit/types/csaf`)
- MCP-Golang (`github.com/metoro-io/mcp-golang`)

## Usage

### Running the Server

```bash
./vex-mcp-server
```

The server communicates via stdio using the MCP protocol.

### Available Tools

#### 1. `lookup_cve`
Look up detailed Red Hat VEX document information for a CVE ID.

**Parameters:**
- `cve` (required): The CVE ID to look up (e.g., "CVE-2024-1234")

**Example:**
```json
{
  "cve": "CVE-2024-1234"
}
```

#### 2. `lookup_rhsa`
Look up detailed Red Hat CSAF advisory information for an RHSA ID.

**Parameters:**
- `rhsa` (required): The RHSA ID to look up (e.g., "RHSA-2024:1234")

**Example:**
```json
{
  "rhsa": "RHSA-2024:1234"
}
```

#### 3. `is_package_affected_by_cve`
Check if a specific package is affected by a CVE.

**Parameters:**
- `cve` (required): The CVE ID to check
- `package` (required): The package name to check if affected
- `limit` (optional): Maximum number of matching products to return (default: 50, max: 500)
- `offset` (optional): Number of matching products to skip (default: 0)

**Example:**
```json
{
  "cve": "CVE-2024-1234",
  "package": "kernel",
  "limit": 20,
  "offset": 0
}
```

#### 4. `is_package_fixed_by_rhsa`
Check if a specific package is fixed by an RHSA.

**Parameters:**
- `rhsa` (required): The RHSA ID to check
- `package` (required): The package name to check if fixed
- `limit` (optional): Maximum number of matching products to return (default: 50, max: 500)
- `offset` (optional): Number of matching products to skip (default: 0)

**Example:**
```json
{
  "rhsa": "RHSA-2024:1234",
  "package": "kernel",
  "limit": 20,
  "offset": 0
}
```

#### 5. `list_affected_packages`
List all packages affected by a CVE or RHSA.

**Parameters:**
- `id` (required): The CVE or RHSA ID to list affected packages for
- `limit` (optional): Maximum number of packages to return per status category (default: 50, max: 500)
- `offset` (optional): Number of packages to skip per status category (default: 0)

**Example:**
```json
{
  "id": "CVE-2024-1234",
  "limit": 25,
  "offset": 0
}
```

#### 6. `resolve_product_identifiers`
Resolve VEX/RHSA product identifiers to their underlying CPE and PURL identifiers.

**Parameters:**
- `id` (required): The CVE or RHSA ID to resolve products for
- `product_ids` (optional): List of specific product IDs to resolve (if empty, resolves all not-affected products)

**Example:**
```json
{
  "id": "CVE-2024-7348",
  "product_ids": ["red_hat_enterprise_linux_10:postgresql", "red_hat_enterprise_linux_10:postgresql-server"]
}
```

**Example - Resolve all not-affected products:**
```json
{
  "id": "CVE-2024-7348"
}
```

### 7. `get_package_vulnerability_status`

Get comprehensive vulnerability status for a specific package across all categories (vulnerable, fixed, not_affected, etc.).

**Parameters:**
- `id` (required): CVE or RHSA ID
- `package` (required): Package name to filter by
- `limit` (optional): Maximum packages per status category (default: 50, max: 500)
- `offset` (optional): Number of packages to skip per category (default: 0)

**Examples:**

**Check PostgreSQL status for a CVE:**
```json
{
  "id": "CVE-2024-7348",
  "package": "postgresql"
}
```

**Check with pagination:**
```json
{
  "id": "CVE-2024-7348", 
  "package": "postgresql",
  "limit": 25,
  "offset": 0
}
```

## Development

### Running Tests

```bash
go test ./vex -v
```

## References

- [Red Hat VEX Documentation](https://www.redhat.com/en/blog/red-hat-vex-files-cves-are-now-generally-available)
- [CSAF Standard](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)
- [Model Context Protocol](https://github.com/anthropics/mcp)
- [Claircore](https://github.com/quay/claircore)
