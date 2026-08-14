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
- **Concurrent Processing**: Parallel API requests with configurable thread pools
- **Rate Limiting**: Token bucket limiter shared across all threads, with global backoff on 429
- **Retries**: Exponential backoff with jitter, honouring `Retry-After`, on 429/5xx/timeouts
- **Completeness Reporting**: Every run ends `COMPLETE` or `INCOMPLETE` and exits non-zero if data is missing
- **Reconciliation Output**: Per-application/context CSV of expected vs retrieved counts
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

### Scope and Filtering

|Argument           |Default |Description                                                         |
|-------------------|--------|--------------------------------------------------------------------|
|`--output`         |`veracode_findings_api.csv`|Output CSV filename                              |
|`--app-name`       |None    |Comma-separated application names (exact match)                     |
|`--app-guid`       |None    |Specific application GUID                                           |
|`--scan-type`      |None    |STATIC, DYNAMIC, MANUAL, SCA, IAC (comma-separated). Omit for all   |
|`--severity`       |None    |Exact severity (0–5)                                                |
|`--severity-gte`   |None    |Severity >= (0–5)                                                   |
|`--cwe`            |None    |CWE ID (single or comma-separated)                                  |
|`--status`         |None    |OPEN or CLOSED. Applied client-side, not an API filter              |
|`--violates-policy`|False   |Only return findings that do not pass policy                        |
|`--include-sandbox`|False   |Include sandbox findings                                            |
|`--max-apps`       |None    |Limit apps processed (testing)                                      |

### Output

|Argument           |Default |Description                                                         |
|-------------------|--------|--------------------------------------------------------------------|
|`--excel-bom`      |False   |Write a UTF-8 BOM so Excel opens non-ASCII correctly. Off by default because the BOM breaks `csv.DictReader`|
|`--raw-json`       |False   |Also write raw API findings as JSON Lines. On a large tenant this file is enormous|
|`--dedup`          |False   |Remove duplicate finding identities. Duplicates are always counted and reported regardless|
|`--no-annotations` |False   |Skip requesting annotations. Leaves Mitigation Comments blank        |

### Performance and Reliability

|Argument           |Default |Description                                                         |
|-------------------|--------|--------------------------------------------------------------------|
|`--rate-limit`     |3.5     |Max API requests/second (210/min, under Veracode's 250/min guidance)|
|`--max-workers`    |5       |Concurrent threads                                                  |
|`--page-size`      |500     |Records per API page                                                |
|`--max-attempts`   |6       |Retry attempts per request                                          |
|`--sleep`          |0.0     |Extra delay between paged requests. Usually unnecessary, the rate limiter already paces requests|
|`--combine-scan-types`|False|Request STATIC,DYNAMIC,MANUAL in one call instead of separately. Fewer calls, but only single `scan_type` values are documented by Veracode|
|`--ignore-failures`|False   |Exit 0 even when requests failed. Not recommended                   |
|`--ca-cert`        |None    |Path to custom CA certificate bundle (.pem). Validated at startup. Required behind SSL inspection devices (e.g. Zscaler)|

## Exit Codes

|Code|Meaning                                                                       |
|----|------------------------------------------------------------------------------|
|0   |Complete. Every request succeeded and every retrieved finding is in the CSV    |
|1   |Incomplete. Some requests failed or counts did not reconcile. See the reconciliation CSV|
|2   |Invalid arguments (e.g. an unrecognised `--scan-type`)                        |
|130 |Interrupted. Nothing was published, the previous output file is untouched     |

Use the exit code to gate a pipeline. A run that prints findings but exits 1 should not be treated as authoritative.

## IaC (Container Security) Integration

IaC findings are fetched automatically on every run. No browser cookies are needed. The script exchanges your existing HMAC API credentials for a short-lived session token (`/api/authn/v2/principal`) and uses it against the Container Security API. The token is refreshed automatically if it expires mid-run.

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

### 1. CSV File (Default: `veracode_findings_api.csv`)

- Primary output containing all findings in tabular format
- One row per finding across all scan types
- Rows are sorted by Application Name, Sandbox Name, Scan Type, Issue ID, so two runs of an unchanged tenant produce identical files and can be diffed
- Written to a temporary file and moved into place only when the run finishes, so an interrupted run never leaves a truncated CSV or destroys the previous export
- Filename customizable via `--output` argument

### 2. Reconciliation CSV (Auto-generated: `<output>_reconciliation_<timestamp>.csv`)

One row per application/context/scan-type request, showing what was expected versus what was retrieved.

|Column                        |Description                                          |
|------------------------------|-----------------------------------------------------|
|Application Name / GUID       |Which application                                     |
|Context                       |`policy` or `sandbox:<name>`                          |
|Scan Type Requested           |STATIC, DYNAMIC, MANUAL, or SCA                       |
|Expected (API total_elements) |Count the API reported for that query                 |
|Retrieved                     |Rows actually collected                               |
|Pages Fetched                 |Pages walked                                          |
|Status                        |`OK`, `MISMATCH`, or `FAILED`                         |
|Detail                        |Reason, when not OK                                   |

Diff this against the platform app-by-app rather than comparing one grand total. Any row that is not `OK` means that context is incomplete.

### 3. Raw JSON Lines (Optional: `veracode_findings_api_raw_<timestamp>.jsonl`)

Only written with `--raw-json`. One JSON object per line containing the complete nested API response for each finding. Useful for debugging or custom processing. It is off by default because on a large tenant it is very large.

**Example:**
```bash
python script.py --app-name "MyApp" --output myapp-findings.csv
```
**Generates:**
- `myapp-findings.csv` - Main CSV output
- `myapp-findings_reconciliation_20260305_143022.csv` - Per-context completeness report

## CSV Columns

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
|Issue ID            |Veracode finding ID. Unique within an application and context. Use with Application ID and Sandbox Name to join against the platform or another export|
|Violates Policy     |Whether the finding fails the assigned policy                         |
|Export Notes        |Normally blank. Populated when a finding could not be fully parsed, so the row is preserved with an explanation instead of being dropped|

### IAC-Specific Columns (IaC Findings Only)

|Column              |Description                                                           |
|--------------------|----------------------------------------------------------------------|
|IAC File Path       |Full file path in repository where IaC issue was found               |
|IAC Start Line      |Starting line number of the finding                                   |
|IAC End Line        |Ending line number of the finding                                     |

**Note:** IAC-specific columns are blank for non-IaC findings. Standard columns may be blank for IaC findings (e.g., CVE ID, CVSS, Fixed Date, Days to Resolve, Resolution Status, Resolution).

## Performance Tuning

Veracode's guidance is to stay under **250 API requests per minute**. The default of `--rate-limit 3.5` is 210/min. Going above roughly 4 req/s will trigger 429 responses; the script warns when you do, retries them, and reports any it cannot recover, but the run will be slower rather than faster.

**Default (recommended for any size):**
```bash
python script.py  # --max-workers 5 --rate-limit 3.5
```

**If you see MISMATCH or FAILED rows in the reconciliation CSV:**
```bash
python script.py --max-workers 3 --rate-limit 2
```

**Fewer API calls per application (trade-off):**
```bash
python script.py --combine-scan-types
```
This requests STATIC, DYNAMIC and MANUAL in a single call instead of three. Veracode documents only single `scan_type` values, so if a combined value is only partially honoured, entire scan types could be missing without an error. Verify counts against the platform before relying on it.

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
   - Creates HTTP sessions with connection pooling
   - Initializes rate limiter with token bucket algorithm

2. **Data Collection Phase**
   - Fetches all application profiles (paginated)
   - Retrieves SCA workspace/project mappings for agent-based findings
   - Fetches Dynamic Analysis scan mappings
   - Filters applications by `--app-name` or `--app-guid` if specified

3. **Concurrent Processing**
   - Applications are submitted to a thread pool in a bounded window, so memory stays flat regardless of tenant size
   - Rate limiter coordinates requests across all threads
   - Results are consumed in submission order so output is reproducible

4. **Finding Extraction (Per Application)**
   - Fetches policy scan findings, one request per scan type
   - Fetches SCA findings separately (Veracode does not support combining SCA with other scan types)
   - If `--include-sandbox`: iterates through all sandboxes and repeats the above
   - Enriches findings with application metadata and deep links
   - Maps SCA Agent findings to workspace/project IDs
   - Maps Dynamic findings to Dynamic Analysis IDs

5. **IaC Integration**
   - Requests a principal session token using the configured HMAC credentials
   - Fetches IaC findings from the Veracode Container Security API
   - Retrieves detailed findings for all IaC scans
   - Matches IaC asset names to Veracode applications
   - Creates placeholder entries for unmatched IaC assets so their findings are still exported
   - Normalizes IaC findings to match standard schema

6. **Post-Processing and Output**
   - Normalizes findings to the common schema, per row, so one malformed record cannot fail the export
   - Strips HTML tags and entities from descriptions
   - Calculates derived fields (Days to Resolve, etc.)
   - Generates Veracode Platform deep links based on scan type
   - Streams rows to the CSV as each application completes
   - Writes the reconciliation CSV and prints a completeness summary

## What This Tool Cannot Retrieve

These are Veracode API behaviours, not script limitations. They will cause legitimate differences against the platform:

- **The Findings API returns the latest policy scan only.** An application whose most recent policy scan covered a subset of modules will differ from aggregated platform views.
- **Applications with only sandbox scans return nothing** unless `--include-sandbox` is used.
- **SCA Agent findings appear only when the agent project is linked to an application profile.** Unlinked workspaces are invisible to this API. On tenants with heavy agent-based SCA use, this is often the largest single difference.
- **Mitigated findings are returned as OPEN** with a resolution status. Platform default views often hide accepted mitigations, so this export can legitimately show more findings than the UI.

For an authoritative tenant-wide extract, consider the Veracode Reporting API (FINDINGS report), which covers Static, Dynamic, MPT, SCA upload and linked SCA agent scans in one job and includes open, closed and mitigated findings. It returns a maximum of six months of data per call and must be enabled for your account by Veracode support.

## Troubleshooting

### Authentication Issues

**401/403 errors** 
- Check API credentials file exists and has correct format
- Verify account has Results API role (Service Account) or Reviewer/Security Lead role (User Account)
- Confirm credentials file location: `~/.veracode/credentials` (Mac/Linux) or `C:\Users\<username>\.veracode\credentials` (Windows)
- Authentication failures are treated as fatal rather than retried, and are reported as failures. The script will not produce an empty CSV and claim success.

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
- These are retried automatically with backoff, and a 429 on any thread pauses all threads
- If they persist, reduce `--rate-limit` (try 2) and `--max-workers` (try 3)
- Avoid running multiple instances simultaneously
- Check if other API clients are running against the same account

**Script running slowly**
- Large tenants take time. The rate limit is the constraint, and raising it above ~4 req/s causes 429s that make the run slower overall
- `--combine-scan-types` reduces calls per application, with the caveat noted under Performance Tuning

### Data Issues

**Export reports INCOMPLETE**
- Open the reconciliation CSV and filter for Status `FAILED` or `MISMATCH`
- `FAILED` means a request could not be completed after all retries
- `MISMATCH` means the API reported a different total than was retrieved, which usually indicates data changing mid-run or throttling
- Re-run with lower `--rate-limit` and `--max-workers`

**CSV has fewer findings than the platform**
- Check `--include-sandbox` is set if you are comparing against sandbox data
- Check the reconciliation CSV for failures
- Review "What This Tool Cannot Retrieve" above, particularly unlinked SCA Agent projects

**Missing CSV fields** 
- Some fields only apply to specific scan types:
  - CVE ID: SCA and IaC vulnerabilities only
  - Sandbox Name: Only populated for sandbox scans
  - Fixed Date: Only when Finding Status = CLOSED or Resolution Status = FIXED
  - Days to Resolve: Only when Fixed Date is available
  - CVSS: Primarily SCA findings
- This is expected behavior, not an error

**Mitigation Comments column is empty**
- Annotations are requested by default. If you passed `--no-annotations`, remove it.

**First column header looks wrong when parsing programmatically**
- Do not use `--excel-bom` if the CSV is being read by a script. The BOM it adds is only for Excel.

### Application-Specific Issues

**404 on specific applications** 
- Application may have no scans yet
- Your account may lack permission for that specific application
- Application may have been deleted or archived

**Sandboxes not appearing**
- Ensure `--include-sandbox` flag is used
- User must have explicit permission to each sandbox
- Some applications may have no sandboxes (not an error)

**SCA Agent findings missing workspace links**
- SCA Agent workspace/project mappings are fetched automatically
- If mappings fail, basic links to the SCA workspace list are provided
- Link generation is separate from finding retrieval, so a mapping failure never removes findings

### Verification

**Test with limited scope:**
```bash
# Test with a single application
python script.py --app-name "TestApp"

# Test API connectivity
python script.py --max-apps 5 --output test.csv
```

**Confirm a run was complete:**
```bash
python script.py --output findings.csv
echo "Exit code: $?"    # 0 = complete, 1 = incomplete
```
Then check the reconciliation CSV for any row where Status is not `OK`.

## Common Use Cases

**Specific applications, all scan types including IaC, plus sandboxes:**
```bash
python script.py --app-name "App1,App2" --include-sandbox
```

**High severity open findings only:**
```bash
python script.py --severity-gte 4 --status OPEN --output high-severity.csv
```

**Full tenant export for audit:**
```bash
python script.py --include-sandbox --output full-export.csv
echo "Exit code: $?"
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
