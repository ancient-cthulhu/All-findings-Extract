# Veracode Findings API Export

A Python script to export vulnerability findings from Veracode using multiple APIs. Iterates through all applications in your Veracode account and retrieves findings for each one, with optional sandbox coverage and IaC (Infrastructure as Code) scan results.

## Prerequisites

### Veracode API Credentials

Requires HMAC authentication. Your account must have one of the following:

- **API Service Account** with the **Results API** role
- **User Account** with the **Reviewer** or **Security Lead** role

Create a credentials file at:

- **Windows:** `C:\Users\<username>\.veracode\credentials`
- **Mac/Linux:** `~/.veracode/credentials`

```ini
[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

Or set environment variables:

```bash
export VERACODE_API_KEY_ID=your_key_id
export VERACODE_API_KEY_SECRET=your_key_secret
```

### Python Requirements

- Python 3.7+
- `requests`
- `veracode-api-signing`

```bash
pip install requests veracode-api-signing
```

## Usage

### Export all findings (policy scans only)

```bash
python script.py
```

### Include sandbox findings

```bash
python script.py --include-sandbox
```

### Filter by application (single or multiple)

**Single application:**
```bash
python script.py --app-name "MyApp"
```

**Multiple applications (comma-separated):**
```bash
python script.py --app-name "Org/Repo"
```

**By GUID:**
```bash
python script.py --app-guid "12345678-1234-1234-1234-123456789abc"
```

> **Note:** When using `--app-name` with comma-separated values, the script performs **exact name matching** (not substring matching) and automatically filters to only those applications.

### Filter by scan type

```bash
python script.py --scan-type STATIC
python script.py --scan-type STATIC,DYNAMIC
python script.py --scan-type SCA
```

> **Note:** SCA findings must be requested separately from other scan types. The script handles this automatically. If you include `SCA` in `--scan-type` alongside others, it will run two separate API passes and merge the results.

### Filter by severity

```bash
python script.py --severity 5
python script.py --severity-gte 3
```

### Filter by status

```bash
python script.py --status OPEN
python script.py --status CLOSED
```

### Filter by CWE

```bash
python script.py --cwe 79
python script.py --cwe 79,89,22
```

### Include IaC (Infrastructure as Code) scan results

```bash
python script.py --iac-json iac-findings.json
```

**With application filtering:**
```bash
python script.py \
  --app-name "Org/Repo" \
  --iac-json iac-findings.json
```

### Combined example

```bash
python script.py \
  --app-name "Org/Repo" \
  --scan-type STATIC \
  --severity-gte 4 \
  --status OPEN \
  --include-sandbox \
  --iac-json iac-findings.json \
  --output high_severity_open.csv
```

## Command-Line Arguments

|Argument           |Default                    |Description                                                         |
|-------------------|---------------------------|--------------------------------------------------------------------|
|`--output`         |`veracode_findings_api.csv`|Output CSV filename                                                 |
|`--app-name`       |None                       |Filter by application name (exact match). Supports comma-separated values for multiple apps|
|`--app-guid`       |None                       |Filter by specific application GUID                                 |
|`--scan-type`      |None                       |STATIC, DYNAMIC, MANUAL, SCA or comma-separated combination         |
|`--severity`       |None                       |Exact severity (0–5)                                                |
|`--severity-gte`   |None                       |Severity greater than or equal to (0–5)                             |
|`--cwe`            |None                       |CWE ID, single or comma-separated                                   |
|`--status`         |None                       |`OPEN` or `CLOSED`                                                  |
|`--include-sandbox`|False                      |Also fetch findings from all development sandboxes                  |
|`--iac-json`       |None                       |Path to IaC scan results JSON file (see IaC section below)          |
|`--sleep`          |`0.01`                     |Seconds to sleep between API pages (default: 0.01)                  |
|`--max-workers`    |`10`                       |Maximum concurrent threads for parallel processing                  |
|`--rate-limit`     |`10.0`                     |Maximum API requests per second across all threads                  |
|`--max-apps`       |None                       |Cap number of apps to process (useful for testing)                  |

## Performance & Scalability

The script uses concurrent processing with thread pooling and intelligent rate limiting for optimal performance:

### Concurrent Processing
- **`--max-workers`**: Controls the number of concurrent threads (default: 10)
- Applications are processed in parallel, significantly reducing total runtime
- Each thread uses its own HTTP session with connection pooling

### Rate Limiting
- **`--rate-limit`**: Maximum API requests per second across all threads (default: 10)
- Uses token bucket algorithm to prevent API throttling (429 errors)
- Automatically distributes rate limit across all worker threads

### Performance Tips
- **Small deployments** (< 50 apps): Default settings work well
- **Large deployments** (100+ apps): Consider increasing `--max-workers 20 --rate-limit 20`
- **Very large deployments** (500+ apps): Test with `--max-workers 30 --rate-limit 30`
- Monitor for 429 errors; reduce rate limit if encountered

### Example - Optimized for Large Scale
```bash
python script.py \
  --max-workers 20 \
  --rate-limit 20 \
  --output all-findings.csv
```

## IaC (Infrastructure as Code) Integration

### Overview

The script can include IaC scan results from Veracode's Container Security alongside regular findings (SAST, DAST, SCA, Manual). Each individual IaC finding becomes a separate row in the output CSV with full details including file paths, line numbers, and rule IDs.

### Quick Start - Fetching IaC Data

Use the included `fetch_iac_details.py` script to fetch detailed IaC findings from Veracode:

#### Step 1: Get your browser session cookies

1. Log into Veracode Platform (proxy as correct org if needed)
2. Open Chrome/Edge Developer Tools (F12)
3. Go to Network tab
4. Refresh the page or navigate to any page
5. Click on any request to `analysiscenter.veracode.com`
6. In Headers section, find **"Cookie:"** and copy the entire value
7. Save it to a file: `cookies.txt`

#### Step 2: Fetch detailed IaC findings

```bash
python fetch_iac_details.py \
  --cookies-file cookies.txt \
  --output iac-findings.json \
  --filter-apps "Org/Repo"
```

This will:
1. Fetch the list of all IaC scans
2. Filter to your specified applications
3. Fetch detailed findings for each scan
4. Save everything to `iac-findings.json`

#### Step 3: Include IaC in your findings export

```bash
python script.py \
  --app-name "Org/Repo" \
  --iac-json iac-findings.json \
  --output complete-findings.csv
```

### IaC Fetcher Script Options

The `fetch_iac_details.py` script supports these arguments:

|Argument            |Description                                                           |
|--------------------|----------------------------------------------------------------------|
|`--cookies-file`    |File containing browser session cookies (recommended)                 |
|`--cookies`         |Browser session cookies as string (use --cookies-file instead)        |
|`--output`          |Output file for detailed findings (default: iac-findings.json)        |
|`--scan-limit`      |Max scans to fetch (default: 5000)                                    |
|`--findings-limit`  |Max findings per scan (default: 1000)                                 |
|`--filter-apps`     |Comma-separated app names to process (optional)                       |
|`--sleep`           |Sleep between API calls in seconds (default: 0.5)                     |

### IaC JSON Structure

The `iac-findings.json` file contains:
```json
{
  "records": [
    {
      "asset_name": "Org/Repo",
      "scan_id": 602410,
      "scanned_at": "2026-03-02T17:45:27.777179",
      "detailed_findings": [
        {
          "severity": "high",
          "title": "Container running as root",
          "description": "Container is running as root user which poses security risks",
          "rule_id": "CIS-DI-0001",
          "file_path": "Dockerfile",
          "line_number": "12"
        }
      ]
    }
  ],
  "metadata": {
    "total_scans": 7,
    "total_findings": 156
  }
}
```

### How IaC Findings Appear in CSV

Each individual IaC finding becomes one row in the CSV with full details:
- **Description**: Full finding description with rule ID (e.g., "Container running as root - Container is running as root user which poses security risks [Rule: CIS-DI-0001]")
- **Vulnerability Title**: Finding title (first 100 chars)
- **Flaw Name**: Finding title
- **CWE ID**: IaC rule ID (e.g., "CIS-DI-0001")
- **Filename/Class**: File path and line number (e.g., "Dockerfile:12")
- **Scan Type**: `IAC`
- **Custom Severity Name**: Very High, High, Medium, Low, Very Low, Informational
- **Severity**: Numeric severity (5=Critical, 4=High, 3=Medium, 2=Low, 1=Negligible, 0=Unknown)
- **First Found Date**: Scan date from IaC record
- **Finding Status**: "OPEN"
- **Team Name**: Extracted from app profile (Business Unit or first team)

### IaC Fields in Output



For each IaC finding, these columns are populated:



- **Application Name**: Name from IaC scan record

- **Application ID**: GUID (matched from app list)

- **Scan Type**: `IAC`

- **Custom Severity Name**: Very High, High, Medium, Low, Very Low, Informational

- **Severity**: Numeric severity (5=Critical, 4=High, 3=Medium, 2=Low, 1=Negligible, 0=Unknown)

- **First Found Date**: Scan date from IaC record

- **Finding Status**: "OPEN"

- **Team Name**: Extracted from app profile

- **Description**: Full finding description with rule ID

- **Vulnerability Title**: Finding title (first 100 chars)

- **CWE ID**: IaC rule ID

- **Flaw Name**: Finding title

- **Filename/Class**: File path and line number



**These columns are always blank for IaC findings:**

- CVE ID, CVSS, Fixed Date, Days to Resolve, Resolution Status, Resolution, Sandbox Name

### IaC Filtering

- IaC findings are **automatically filtered** to match your `--app-name` list
- Only IaC scans for applications in your filtered list are included
- The script validates that the IaC JSON contains detailed findings
- The script shows scan counts and total findings during processing

### Manual Method (Not Recommended)

The manual method only provides summary counts (not individual findings), so it's **not compatible** with this script:

1. **Summary data URL** (not sufficient):
   ```
   https://ui.analysiscenter.veracode.com/container-scan-query/v1/scans?page=0&limit=5000
   ```
   This only gives you severity counts, not individual finding details.

2. **Use the fetcher script instead**:
   ```bash
   python fetch_iac_details.py --cookies-file cookies.txt
   ```
   The fetcher script automatically gets both the summary and detailed findings for you.

### Example Output with IaC

```
======================================================================
  PROCESSING IAC SCAN DATA
======================================================================

✓ Loaded IaC data from iac-findings.json
  Found 7 IaC scans with 156 total findings

  Processing detailed IaC findings...

  Processing Org/Repo: 39 findings
  Processing Org/Repo: 12 findings
  ...

  ✓ Processed 7 applications
  ✓ Added 156 individual IaC findings

======================================================================
  EXPORT COMPLETED
======================================================================
  Applications processed    : 7
  Applications with findings: 7
  Total findings            : 1417
    - Regular scan findings : 1261
    - IaC scan findings     : 156
======================================================================
```

## Output Files

### CSV - `veracode_findings_api.csv`

|Column              |Description                                                           |
|--------------------|----------------------------------------------------------------------|
|Application Name    |Application profile name                                              |
|Application ID      |Application GUID                                                      |
|Sandbox Name        |Sandbox name if finding is from a sandbox; blank for policy scan      |
|Custom Severity Name|Very High / High / Medium / Low / Very Low / Informational            |
|CVE ID              |CVE identifier (SCA findings only)                                    |
|Description         |Finding description                                                   |
|Vulnerability Title |First 100 characters of description                                   |
|CWE ID              |CWE numeric ID (or IaC Rule ID for IaC findings)                      |
|Flaw Name           |CWE name or finding category                                          |
|First Found Date    |Date the finding was first observed                                   |
|Filename/Class      |File, path, URL, or component — varies by scan type                   |
|Finding Status      |`OPEN` or `CLOSED`                                                    |
|Fixed Date          |Resolution date; falls back to last seen date if not available        |
|Team Name           |Business unit name or first assigned team from the application profile|
|Days to Resolve     |Days between first found and fixed date                               |
|Scan Type           |STATIC, Dynamic Analysis, DAST, MANUAL, SCA, SCA Agent, or IAC       |
|CVSS                |CVSS score (prefers v3 for SCA)                                       |
|Severity            |Numeric severity 0–5                                                  |
|Resolution Status   |Resolution status from the platform                                   |
|Resolution          |Resolution type                                                       |
|Veracode Link       |Deep link to finding in Veracode Platform (format varies by scan type)|

### JSON — `veracode_findings_api_raw_<timestamp>.json`

Raw API response data for all findings, saved for debugging.

## How It Works

1. Fetches all application profiles via the Applications API (paginated)
2. Fetches SCA workspace/project mappings for agent-based SCA findings
3. Fetches Dynamic Analysis mappings for web application scanning findings
4. Filters applications based on `--app-name` (comma-separated exact matches) or `--app-guid`
5. Processes applications concurrently using thread pool (configurable via `--max-workers`)
6. For each application, runs findings API calls with rate limiting:
   - **Policy scan** — always fetched (no `context` parameter)
   - **Sandboxes** — fetched per sandbox using `?context={sandbox_guid}` if `--include-sandbox` is set
   - **SCA** — always fetched in a dedicated separate pass, as required by the Veracode API
7. If `--iac-json` is provided:
   - Loads IaC detailed findings from the JSON file
   - Validates that the file contains detailed findings (not just summary counts)
   - Matches IaC scans to applications by name
   - Creates one row per individual IaC finding with full details
   - Filters to only include applications in your filtered list
8. Normalizes fields across scan types and calculates derived values (e.g. days to resolve)
9. Generates deep links to findings in Veracode Platform based on scan type
10. Writes results to CSV and raw JSON

## Severity Mapping

|Numeric|Label        |
|-------|-------------|
|5      |Very High    |
|4      |High         |
|3      |Medium       |
|2      |Low          |
|1      |Very Low     |
|0      |Informational|

## Troubleshooting

**401 / 403** — Check credentials file format and that your account has the Results API or Reviewer role.

**0 applications returned** — Verify your account has access to application profiles and you're using the correct API region.

**404 on specific applications** — Normal; the app likely has no scans yet or your account lacks permission for that profile. The script skips and continues.

**429 Too Many Requests** — Increase `--sleep` (e.g. `--sleep 1.5`). Avoid running multiple instances simultaneously.

**Missing fields in CSV** — CVE ID is SCA-only. Sandbox Name is blank for policy scan findings. Fixed Date requires the finding to be CLOSED or FIXED. CWE ID contains the IaC rule ID for IaC findings (not a CWE number).

**IaC file not found** — Ensure the path to your IaC JSON file is correct. Use absolute or relative paths.

**IaC wrong format error** — The script requires detailed findings, not summary counts. Use `fetch_iac_details.py` to fetch the correct format.

**IaC applications not matched** — IaC matching is **case-sensitive and exact**. Ensure the `asset_name` in your IaC JSON exactly matches the application names in Veracode. The script will warn you if applications are not found.

**IaC cookies expired** — Browser session cookies typically expire after a few hours. Get fresh cookies from your browser and update `cookies.txt`.

## Use Case Examples

### Export findings for specific applications

```bash
python script.py \
  --app-name "Org/Repo" \
  --output Org-repo.csv
```

### Export findings including IaC for specific applications

```bash
# Step 1: Fetch IaC data
python fetch_iac_details.py \
  --cookies-file cookies.txt \
  --output iac-findings.json \
  --filter-apps "Org/Repo"

# Step 2: Export all findings
python script.py \
  --app-name "Org/Repo" \
  --iac-json iac-findings.json \
  --include-sandbox \
  --output Org-Repo-complete.csv
```

### Export only high severity open findings with IaC

```bash
python script.py \
  --app-name "Org/Repo" \
  --severity-gte 4 \
  --status OPEN \
  --iac-json iac-findings.json \
  --output high-severity-open.csv
```

## API References

- [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro)
- [Applications REST API](https://docs.veracode.com/r/c_apps_intro)
- [Container Security (IaC Scans)](https://docs.veracode.com/r/Veracode_Container_Security)
- [API Authentication](https://docs.veracode.com/r/t_install_api_authen)

## License

This is a community tool and is not officially supported by Veracode.
