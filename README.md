# Veracode Findings API Export

Export vulnerability findings from Veracode across all scan types (SAST, DAST, SCA, Manual, IaC) into a single CSV file.

## Prerequisites

### API Credentials

Requires one of:
- **API Service Account** with **Results API** role (recommended for org-wide access)
- **User Account** with **Reviewer** or **Security Lead** role (limited to assigned teams)

**Setup:**
```ini
# Windows: C:\Users\<username>\.veracode\credentials
# Mac/Linux: ~/.veracode/credentials

[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

### Python Requirements
```bash
pip install requests veracode-api-signing veracode-api-py
```

## Features

- **Comprehensive Coverage**: Exports findings from all Veracode scan types:
  - Static Analysis (SAST)
  - Dynamic Analysis (DAST) 
  - Software Composition Analysis (SCA & SCA Agent)
  - Manual Penetration Testing
  - Infrastructure as Code (Container Security)
- **Concurrent Processing**: Parallel API requests with configurable thread pools for fast exports
- **Rate Limiting**: Built-in token bucket algorithm prevents API throttling
- **Smart Filtering**: Filter by application, scan type, severity, CWE, status
- **Sandbox Support**: Optionally include findings from development sandboxes

## Quick Start

**Export all findings:**
```bash
python script.py
```

**Filter by applications:**
```bash
python script.py --app-name "App1,App2,App3"
```

**Include sandboxes + high severity only:**
```bash
python script.py --include-sandbox --severity-gte 4 --status OPEN
```

**Limit to a single scan type:**
```bash
python script.py --scan-type IAC
```

## Command-Line Arguments

|Argument           |Default |Description                                                         |
|-------------------|--------|--------------------------------------------------------------------|
|`--output`         |`veracode_findings_api.csv`|Output CSV filename                              |
|`--app-name`       |None    |Comma-separated application names (exact match)                     |
|`--app-guid`       |None    |Specific application GUID                                           |
|`--scan-type`      |None    |STATIC, DYNAMIC, MANUAL, SCA, IAC (comma-separated)                 |
|`--severity`       |None    |Exact severity (0–5)                                                |
|`--severity-gte`   |None    |Severity >= (0–5)                                                   |
|`--cwe`            |None    |CWE ID (single or comma-separated)                                  |
|`--status`         |None    |OPEN or CLOSED                                                      |
|`--include-sandbox`|False   |Include sandbox findings                                            |
|`--sleep`          |0.01    |Delay in seconds between paged requests                             |
|`--max-workers`    |10      |Concurrent threads for parallel processing                          |
|`--rate-limit`     |10.0    |Max API requests/second                                             |
|`--max-apps`       |None    |Limit apps processed (testing)                                      |
| `--ca-cert` | - | Path to custom CA certificate bundle (.pem). Validated at startup, produces a clear error if the file doesn't exist. Required behind SSL inspection devices (e.g. Zscaler). |

## IaC (Container Security) Integration

IaC findings are fetched automatically on every run. No browser cookies are needed. The script exchanges your existing HMAC API credentials for a short-lived session token (`/api/authn/v2/principal`) and uses it against the Container Security API.

**Default run (includes IaC):**
```bash
python script.py
```

**IaC only:**
```bash
python script.py --scan-type IAC
```

**Exclude IaC:**
```bash
python script.py --scan-type STATIC,DYNAMIC,MANUAL,SCA
```

**Filter specific applications:**
```bash
python script.py --scan-type IAC --app-name "App1,App2"
```

## Output Files

The script generates two output files:

### 1. CSV File (Default: `veracode_findings_api.csv`)

- Primary output containing all findings in tabular format
- One row per finding across all scan types
- Can be opened in Excel, imported into databases, or processed by other tools
- Filename customizable via `--output` argument

### 2. JSON File (Auto-generated: `veracode_findings_api_raw_<timestamp>.json`)

- Raw API response data for all findings
- Includes complete nested data structures from Veracode APIs
- Useful for debugging, advanced analysis, or custom processing
- Automatically timestamped to avoid overwriting previous exports
- Contains all metadata that may not fit in CSV format

**Example:**
```bash
python script.py --app-name "MyApp" --output myapp-findings.csv
```
**Generates:**
- `myapp-findings.csv` - Main CSV output
- `veracode_findings_api_raw_20260305_143022.json` - Raw JSON data



### Standard Columns (All Scan Types)

|Column              |Description                                                           |
|--------------------|----------------------------------------------------------------------|
|Application Name    |Application name from Veracode profile                                |
|Application ID      |Application GUID                                                      |
|Sandbox Name        |Sandbox name (blank for policy scans and IaC)                         |
|Custom Severity Name|Very High / High / Medium / Low / Very Low / Informational            |
|CVE ID              |CVE identifier (SCA/IaC vulnerabilities only). **IaC**: Finding ID if vulnerability type|
|Description         |Full finding description (HTML tags stripped). **IaC**: Title + description + finding ID|
|Vulnerability Title |Finding title or first 100 chars of description. **IaC**: Finding type (e.g., "Vulnerability", "Misconfiguration")|
|CWE ID              |CWE numeric ID. **IaC**: Rule/Policy ID (e.g., "CIS-DI-0001")        |
|Flaw Name           |CWE name, finding category, or title. **IaC**: Finding ID or title   |
|First Found Date    |ISO 8601 date when finding was first observed. **IaC**: Scan date    |
|Filename/Class      |File path (STATIC), URL (DYNAMIC), component (SCA). **IaC**: File path with line numbers (e.g., "Dockerfile (Lines 12-15)")|
|Finding Status      |OPEN or CLOSED. **IaC**: Always OPEN                                  |
|Fixed Date          |Resolution date (ISO 8601) - only populated when CLOSED/FIXED. **IaC**: Always blank|
|Team Name           |Business unit name or first team from application profile             |
|Days to Resolve     |Calculated days between first found and fixed. **IaC**: Always blank |
|Scan Type           |STATIC, Dynamic Analysis, DAST, MANUAL, SCA, SCA Agent, or **IAC**   |
|CVSS                |CVSS score (prefers v3 for SCA). **IaC**: CVSS from finding if available|
|Severity            |Numeric severity: 5=Very High, 4=High, 3=Medium, 2=Low, 1=Very Low, 0=Informational. **IaC**: Mapped from critical/high/medium/low/negligible/unknown|
|Resolution Status   |Resolution status from Veracode platform. **IaC**: Always blank       |
|Resolution          |Resolution type (e.g., APPROVED, FALSE POSITIVE, etc.). **IaC**: Always blank|
|Mitigation Comments |Comments from annotations/mitigations. **IaC**: Suggested fix text    |
|Veracode Link       |Deep link to finding in Veracode Platform (format varies by scan type). **IaC**: Link to Container Security scan|

### IAC-Specific Columns (IaC Findings Only)

|Column              |Description                                                           |
|--------------------|----------------------------------------------------------------------|
|IAC File Path       |Full file path in repository where IaC issue was found               |
|IAC Start Line      |Starting line number of the finding                                   |
|IAC End Line        |Ending line number of the finding                                     |

**Note:** IAC-specific columns are blank for non-IaC findings. Standard columns may be blank for IaC findings (e.g., CVE ID, CVSS, Fixed Date, Days to Resolve, Resolution Status, Resolution).

## Performance Tuning

**Default (< 50 apps):**
```bash
python script.py  # Uses --max-workers 10 --rate-limit 10
```

**Large deployments (100+ apps):**
```bash
python script.py --max-workers 20 --rate-limit 20
```

**Very large (500+ apps):**
```bash
python script.py --max-workers 30 --rate-limit 30
```

## Severity Mapping

|Numeric|Label        |
|-------|-------------|
|5      |Very High    |
|4      |High         |
|3      |Medium       |
|2      |Low          |
|1      |Very Low     |
|0      |Informational|

## How It Works

### Execution Flow

1. **Initialization**
   - Validates API credentials
   - Creates optimized HTTP sessions with connection pooling
   - Initializes rate limiter with token bucket algorithm

2. **Data Collection Phase**
   - Fetches all application profiles (paginated, supports 1000s of apps)
   - Retrieves SCA workspace/project mappings for agent-based findings
   - Fetches Dynamic Analysis scan mappings
   - Filters applications by `--app-name` or `--app-guid` if specified

3. **Concurrent Processing**
   - Submits all applications to thread pool executor
   - Each worker thread processes one application at a time
   - Rate limiter coordinates requests across all threads
   - Applications are processed in parallel for optimal performance

4. **Finding Extraction (Per Application)**
   - Fetches policy scan findings (all scan types except SCA)
   - Fetches SCA findings separately
   - If `--include-sandbox`: iterates through all sandboxes and repeats above
   - Enriches findings with application metadata and deep links
   - Maps SCA Agent findings to workspace/project IDs
   - Maps Dynamic findings to Dynamic Analysis IDs

5. **IaC Integration**
   - Requests a principal session token using the configured HMAC credentials
   - Fetches IaC findings directly from the Veracode Container Security API
   - Retrieves detailed findings for all IaC scans
   - Matches IaC asset names to Veracode applications using fuzzy logic
   - Creates placeholder entries for unmatched IaC assets
   - Normalizes IaC findings to match standard schema

6. **Post-Processing**
   - Normalizes all findings to common schema
   - Strips HTML tags and entities from descriptions
   - Calculates derived fields (Days to Resolve, etc.)
   - Generates Veracode Platform deep links based on scan type

7. **Output Generation**
   - Writes raw JSON with complete API responses (timestamped)
   - Writes normalized CSV with all findings
   - Displays summary statistics


## Troubleshooting

### Authentication Issues

**401/403 errors** 
- Check API credentials file exists and has correct format
- Verify account has Results API role (Service Account) or Reviewer/Security Lead role (User Account)
- Confirm credentials file location: `~/.veracode/credentials` (Mac/Linux) or `C:\Users\<username>\.veracode\credentials` (Windows)

**IaC authentication failed** 
- The script requests a session token via `/api/authn/v2/principal` using your HMAC credentials
- Confirm the account has access to Container Security / IaC scans in the platform
- Confirm `veracode-api-py` is installed (the token call uses `APIHelper`)

**0 applications returned** 
- User accounts only see applications assigned to their teams/business units
- API Service Accounts see all applications in the organization
- Verify you're querying the correct API region (US/EU)
- Test with `--max-apps 5` to verify API connectivity

### Performance Issues

**429 Too Many Requests** 
- Reduce `--rate-limit` (try `--rate-limit 5` or lower)
- Reduce `--max-workers` (try `--max-workers 5`)
- Avoid running multiple instances simultaneously
- Check if other API clients are running against same account

**Script running slowly**
- Increase `--max-workers` for large deployments (20-30 for 100+ apps)
- Increase `--rate-limit` if not encountering 429 errors
- Note: Large applications with many findings will naturally take longer

### Data Issues

**Missing CSV fields** 
- Some fields only apply to specific scan types:
  - CVE ID: SCA and IaC vulnerabilities only
  - Sandbox Name: Only populated for sandbox scans
  - Fixed Date: Only when Finding Status = CLOSED or Resolution Status = FIXED
  - Days to Resolve: Only when Fixed Date is available
  - CVSS: Primarily SCA findings
- This is expected behavior, not an error

**IaC applications not matched**
- IaC matching uses fuzzy logic to match asset names to application names
- If no match found, IaC findings are still included with placeholder app profile
- Check console output for "No matching application found" warnings
- Verify asset names in IaC scans match application names in Veracode

### Application-Specific Issues

**404 on specific applications** 
- Application may have no scans yet
- Your account may lack permission for that specific application
- Application may have been deleted or archived
- Script will skip and continue with other applications (expected behavior)

**Sandboxes not appearing**
- Ensure `--include-sandbox` flag is used
- User must have explicit permission to each sandbox
- Some applications may have no sandboxes (not an error)

**SCA Agent findings missing workspace links**
- SCA Agent workspace/project mappings are fetched automatically
- If mappings fail, basic links to SCA workspace list are provided
- This is a fallback and doesn't affect other data

### Verification

**Test with limited scope:**
```bash
# Test with single application
python script.py --app-name "TestApp" --max-apps 1

# Test API connectivity
python script.py --max-apps 5 --output test.csv
```

**Check raw JSON output:**
- Review `veracode_findings_api_raw_<timestamp>.json` for complete API responses
- Useful for debugging missing data or unexpected behavior

## Common Use Cases

**Specific applications, all scan types including IaC, plus sandboxes:**
```bash
python script.py --app-name "App1,App2" --include-sandbox
```

**High severity open findings only:**
```bash
python script.py --severity-gte 4 --status OPEN --output high-severity.csv
```

**Testing with limited apps:**
```bash
python script.py --max-apps 5
```

## API References

- [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro)
- [Applications REST API](https://docs.veracode.com/r/c_apps_intro)
- [API Authentication](https://docs.veracode.com/r/t_install_api_authen)

---

**Note:** This is a community tool and is not officially supported by Veracode.
