#!/usr/bin/env python3
"""Export vulnerability findings from Veracode across all scan types into a single CSV.

Covers SAST, DAST, SCA, Manual, and IaC scan types with concurrent API processing,
rate limiting, and optional sandbox inclusion.

"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import html
import json
import os
import random
import re
import itertools
import sys
import threading
import time
from collections import Counter as CollCounter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from veracode_api_py.apihelper import APIHelper


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL = "https://api.veracode.com"
APPLICATIONS_URL = f"{BASE_URL}/appsec/v1/applications"
SANDBOXES_URL_TEMPLATE = f"{BASE_URL}/appsec/v1/applications/{{app_guid}}/sandboxes"
FINDINGS_URL_TEMPLATE = f"{BASE_URL}/appsec/v2/applications/{{app_guid}}/findings"
SCA_API_BASE = f"{BASE_URL}/srcclr/v3"
DYNAMIC_ANALYSES_URL = f"{BASE_URL}/was/configservice/v1/analyses"
ANALYSIS_CENTER_BASE = "https://analysiscenter.veracode.com/auth/index.jsp"

# 500 is the documented safe maximum for Veracode REST collection endpoints.
DEFAULT_PAGE_SIZE = 500
NON_SCA_SCAN_TYPES = ("STATIC", "DYNAMIC", "MANUAL")
MAX_ERROR_BODY_LOG = 500

# Retry policy
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
DEFAULT_MAX_ATTEMPTS = 6
DEFAULT_BASE_BACKOFF = 1.5
MAX_BACKOFF = 90.0

# Veracode documents a 250 request/minute guidance. Warn above this.
SAFE_RPS = 4.0

# Hard backstop against an endpoint that advertises a next page forever.
# At the default page size this is 5,000,000 records in one context, far
# beyond any real application, so hitting it means something is wrong.
MAX_PAGES_SAFETY_CAP = 10_000

# IaC / Container Security API (uses principal token auth, not HMAC)
IAC_API_BASE = "https://ui.analysiscenter.veracode.com/container-scan-query/v1"
IAC_SCANS_URL = f"{IAC_API_BASE}/scans"
IAC_FINDINGS_URL_TEMPLATE = f"{IAC_API_BASE}/scans/{{scan_id}}/findings"
IAC_AUTH_TOKEN_PREFIX = "VERACODE-TOKEN vsid="
IAC_MAX_RECORDS = 5000

# Pre-compiled regexes for the hot-path in strip_html_tags
_RE_HTML_TAG = re.compile(r"<[^>]+>")
_RE_WHITESPACE = re.compile(r"\s+")

SEVERITY_LABEL: dict[int, str] = {
    5: "Very High",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Very Low",
    0: "Informational",
}

IAC_SEVERITY_MAP: dict[str, tuple[int, str]] = {
    "critical": (5, "Very High"),
    "high": (4, "High"),
    "medium": (3, "Medium"),
    "low": (2, "Low"),
    "negligible": (1, "Very Low"),
    "unknown": (0, "Informational"),
}

CSV_FIELDNAMES: list[str] = [
    "Application Name",
    "Application ID",
    "Sandbox Name",
    "Custom Severity Name",
    "CVE ID",
    "Description",
    "Vulnerability Title",
    "CWE ID",
    "Flaw Name",
    "First Found Date",
    "Filename/Class",
    "Finding Status",
    "Fixed Date",
    "Team Name",
    "Days to Resolve",
    "Scan Type",
    "CVSS",
    "Severity",
    "Resolution Status",
    "Resolution",
    "Mitigation Comments",
    "Veracode Link",
    "IAC File Path",
    "IAC Start Line",
    "IAC End Line",
    "Issue ID",
    "Violates Policy",
    "Export Notes",
]

RECON_FIELDNAMES: list[str] = [
    "Application Name",
    "Application GUID",
    "Context",
    "Scan Type Requested",
    "Expected (API total_elements)",
    "Retrieved",
    "Pages Fetched",
    "Status",
    "Detail",
]

VALID_SCAN_TYPES = frozenset({"STATIC", "DYNAMIC", "MANUAL", "SCA", "IAC"})
API_SCAN_TYPES = frozenset({"STATIC", "DYNAMIC", "MANUAL", "SCA"})


def _parse_requested_scan_types(scan_type_str: Optional[str]) -> list[str]:
    """Parse a comma-separated scan-type string into an uppercase list."""
    if not scan_type_str:
        return []
    return [s.strip().upper() for s in scan_type_str.split(",") if s.strip()]


# ---------------------------------------------------------------------------
# Failure Tracking
# ---------------------------------------------------------------------------

class FetchError(Exception):
    """Raised when a request could not be completed after all retries."""


class FailureTracker:
    """Thread-safe register of irrecoverable failures and count mismatches.

    The original script printed errors and carried on, so a run that lost
    half its data still ended with 'EXPORT COMPLETED'. Everything recorded
    here is surfaced in the final summary and drives the process exit code.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.failures: list[dict[str, str]] = []
        self.mismatches: list[dict[str, str]] = []
        self.retries = 0
        self.rate_limit_hits = 0
        self.pages_ok = 0
        self.pages_failed = 0

    def record_failure(self, scope: str, detail: str) -> None:
        with self._lock:
            self.failures.append({"scope": scope, "detail": detail})

    def record_mismatch(self, scope: str, expected: int, retrieved: int) -> None:
        with self._lock:
            self.mismatches.append({
                "scope": scope,
                "detail": f"expected {expected}, retrieved {retrieved}",
            })

    def record_page(self, ok: bool) -> None:
        with self._lock:
            if ok:
                self.pages_ok += 1
            else:
                self.pages_failed += 1

    def record_retry(self, was_rate_limit: bool) -> None:
        with self._lock:
            self.retries += 1
            if was_rate_limit:
                self.rate_limit_hits += 1

    @property
    def clean(self) -> bool:
        return not self.failures and not self.mismatches


# ---------------------------------------------------------------------------
# Session Factory
# ---------------------------------------------------------------------------

def create_session(ca_cert: Optional[str] = None, use_hmac: bool = True) -> requests.Session:
    """Create an HTTP session with connection pooling and optional custom CA cert.

    Note: no urllib3-level retries are configured. urllib3's default Retry has
    an empty status_forcelist, so it would not retry 429/5xx anyway. Retries
    are handled explicitly in request_with_retry so that Retry-After is
    honoured and failures are recorded.
    """
    if ca_cert and not os.path.isfile(ca_cert):
        raise FileNotFoundError(
            f"CA certificate file not found: {ca_cert}\n"
            "If DER-encoded (.cer), convert first: "
            "openssl x509 -inform DER -in corp-ca.cer -out corp-ca.pem"
        )

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=50,
        max_retries=0,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if ca_cert:
        session.verify = ca_cert
    if use_hmac:
        session.auth = RequestsAuthPluginVeracodeHMAC()
    return session


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe token-bucket rate limiter with global cooperative backoff.

    Key design choices:
    - ``time.sleep()`` is called **outside** the lock so sleeping threads do
      not prevent others from acquiring tokens that have become available.
    - Uses ``time.monotonic()`` to be immune to NTP / wall-clock adjustments.
    - ``pause()`` lets one thread that received a 429 stall every other
      thread. Without this, ten workers keep hammering a throttled endpoint
      and every one of them burns its retry budget.
    """

    def __init__(self, requests_per_second: float = 3.5) -> None:
        self._rps = requests_per_second
        self._tokens = float(requests_per_second)
        self._max_tokens = float(requests_per_second)
        self._last_update = time.monotonic()
        self._pause_until = 0.0
        self._lock = threading.Lock()

    def pause(self, seconds: float) -> None:
        """Stall all callers for at least *seconds* (global backoff)."""
        with self._lock:
            target = time.monotonic() + seconds
            if target > self._pause_until:
                self._pause_until = target

    def acquire(self) -> None:
        """Block until a token is available, then consume it."""
        while True:
            with self._lock:
                now = time.monotonic()

                if now < self._pause_until:
                    sleep_needed = self._pause_until - now
                else:
                    elapsed = now - self._last_update
                    self._tokens = min(
                        self._max_tokens,
                        self._tokens + elapsed * self._rps,
                    )
                    self._last_update = now

                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return  # token acquired, lock released
                    sleep_needed = (1.0 - self._tokens) / self._rps

            # Sleep WITHOUT holding the lock
            time.sleep(sleep_needed)


# ---------------------------------------------------------------------------
# Request Layer (retry + backoff + failure recording)
# ---------------------------------------------------------------------------

def _retry_after_seconds(resp: requests.Response) -> Optional[float]:
    """Parse the Retry-After header (seconds form or HTTP-date form)."""
    raw = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        pass
    try:
        when = dt.datetime.strptime(raw, "%a, %d %b %Y %H:%M:%S %Z")
        # utcnow() is deprecated from Python 3.12; use an aware UTC clock and
        # attach UTC to the parsed value, which %Z leaves naive.
        now = dt.datetime.now(dt.timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        return max(0.0, (when - now).total_seconds())
    except (TypeError, ValueError):
        return None


def request_with_retry(
    session: requests.Session,
    url: str,
    *,
    scope: str,
    rate_limiter: Optional[RateLimiter] = None,
    tracker: Optional[FailureTracker] = None,
    max_attempts: Optional[int] = None,
    ok_statuses: tuple[int, ...] = (200,),
    passthrough_statuses: tuple[int, ...] = (404,),
    auth_refresh: Optional[Any] = None,
    **kwargs: Any,
) -> requests.Response:
    """GET *url* with rate limiting and retries.

    Retries on connection errors, timeouts and RETRYABLE_STATUS codes,
    honouring Retry-After when present. Raises FetchError when the request
    cannot be completed. Statuses in *passthrough_statuses* are returned to
    the caller as-is so it can decide (404 usually means 'no data here').

    *auth_refresh*, when supplied, is called once on a 401 to mint a fresh
    credential and returns replacement headers. This exists for the IaC
    principal token, which is obtained once and can expire part-way through
    a long run. Without it an expiry turns every remaining IaC request into
    a hard failure.
    """
    last_detail = "unknown"
    auth_refreshed = False
    # Resolved here rather than as a default argument, because default
    # arguments bind once at definition time and would ignore --max-attempts.
    if max_attempts is None:
        max_attempts = DEFAULT_MAX_ATTEMPTS
    max_attempts = max(1, max_attempts)

    for attempt in range(1, max_attempts + 1):
        if rate_limiter:
            rate_limiter.acquire()

        retry_after: Optional[float] = None
        try:
            resp = session.get(url, **kwargs)
        except requests.RequestException as exc:
            last_detail = f"{type(exc).__name__}: {str(exc)[:200]}"
        else:
            if resp.status_code in ok_statuses:
                return resp
            if resp.status_code in passthrough_statuses:
                return resp
            if resp.status_code == 401 and auth_refresh and not auth_refreshed:
                # Credential expired mid-run. Mint a new one and retry this
                # exact request once before giving up.
                auth_refreshed = True
                try:
                    new_headers = auth_refresh()
                except Exception as exc:
                    raise FetchError(
                        f"{scope}: HTTP 401 and credential refresh failed: {exc}"
                    ) from exc
                if new_headers:
                    kwargs["headers"] = {**(kwargs.get("headers") or {}), **new_headers}
                print(f"    AUTH refreshed after 401 [{scope}]; retrying")
                continue
            if resp.status_code not in RETRYABLE_STATUS:
                body = resp.text[:MAX_ERROR_BODY_LOG] if resp.text else ""
                raise FetchError(
                    f"{scope}: non-retryable HTTP {resp.status_code}. {body}"
                )
            last_detail = f"HTTP {resp.status_code}"
            retry_after = _retry_after_seconds(resp)
            if resp.status_code == 429 and rate_limiter:
                # Stall every worker, not just this one.
                rate_limiter.pause(retry_after if retry_after is not None else 30.0)

        if tracker:
            tracker.record_retry(was_rate_limit=last_detail == "HTTP 429")

        if attempt == max_attempts:
            break

        if retry_after is not None:
            delay = retry_after
        else:
            delay = min(MAX_BACKOFF, DEFAULT_BASE_BACKOFF * (2 ** (attempt - 1)))
        delay += random.uniform(0.0, 0.3 * max(delay, 0.5))  # jitter
        print(f"    RETRY {attempt}/{max_attempts - 1} [{scope}] after {last_detail}; "
              f"sleeping {delay:.1f}s")
        time.sleep(delay)

    raise FetchError(f"{scope}: exhausted {max_attempts} attempts. Last error: {last_detail}")


# ---------------------------------------------------------------------------
# HAL Helpers
# ---------------------------------------------------------------------------

def _get_embedded(data: dict, key: str) -> list[dict]:
    """Safely extract ``data["_embedded"][key]``, defaulting to ``[]``."""
    return (data.get("_embedded") or {}).get(key, []) or []


def _page_meta(data: dict) -> tuple[Optional[int], Optional[int]]:
    """Return ``(total_pages, total_elements)`` from a HAL page block."""
    page = data.get("page") or {}
    tp = page.get("total_pages")
    te = page.get("total_elements")
    return (
        int(tp) if isinstance(tp, (int, float)) else None,
        int(te) if isinstance(te, (int, float)) else None,
    )


def _has_next(data: dict) -> bool:
    return bool((data.get("_links") or {}).get("next"))


def paginate(
    session: requests.Session,
    url: str,
    embedded_key: str,
    *,
    scope: str,
    rate_limiter: Optional[RateLimiter],
    tracker: Optional[FailureTracker],
    params: Optional[dict[str, Any]] = None,
    page_size: int = DEFAULT_PAGE_SIZE,
    timeout: int = 120,
    sleep_time: float = 0.0,
    max_pages: int = MAX_PAGES_SAFETY_CAP,
    on_page: Optional[Any] = None,
) -> tuple[list[dict], Optional[int], int]:
    """Walk every page of a Veracode HAL collection.

    Stop conditions, in order of safety:

    - The walk continues while EITHER ``_links.next`` is present OR
      ``page.total_pages`` says more pages remain. Trusting ``total_pages``
      alone is unsafe: on a large tenant the count can be stale or computed
      against a snapshot taken before the walk finished, and believing it
      truncates the walk exactly like the bug this script exists to fix.
      Only when both signals agree there is no more data do we stop.
    - An empty page ends the walk only when no next link is advertised, so a
      single sparse page cannot end it early.
    - ``max_pages`` is a hard backstop against an API that advertises a next
      link forever. Hitting it is recorded as a failure, never silently.

    Returns ``(records, total_elements_reported, pages_fetched)``.
    Raises FetchError if any page could not be retrieved.
    """
    base_params = dict(params or {})
    base_params["size"] = page_size

    records: list[dict] = []
    total_elements: Optional[int] = None
    total_pages: Optional[int] = None
    page = 0
    pages_fetched = 0
    empty_streak = 0

    while True:
        req_params = dict(base_params)
        req_params["page"] = page

        resp = request_with_retry(
            session, url,
            scope=f"{scope} page {page}",
            rate_limiter=rate_limiter,
            tracker=tracker,
            params=req_params,
            timeout=timeout,
        )
        if resp.status_code == 404:
            break

        try:
            data = resp.json()
        except ValueError as exc:
            raise FetchError(f"{scope} page {page}: invalid JSON response ({exc})") from exc

        pages_fetched += 1
        if tracker:
            tracker.record_page(ok=True)
        batch = _get_embedded(data, embedded_key)
        tp, te = _page_meta(data)
        if te is not None:
            total_elements = te
        if tp is not None:
            total_pages = tp

        if batch:
            records.extend(batch)
            empty_streak = 0
            if on_page:
                on_page(page, batch, len(records), total_elements)
        else:
            empty_streak += 1

        # --- Stop logic -------------------------------------------------
        # Each signal may independently claim there is more data. Only stop
        # when none of them does.
        next_link = _has_next(data)
        meta_says_more = total_pages is not None and page < total_pages - 1
        count_says_more = (
            total_elements is not None and len(records) < total_elements
        )

        if not (next_link or meta_says_more or count_says_more):
            break

        # An API that advertises more but keeps returning nothing would spin
        # forever. Two consecutive empty pages means it has nothing left.
        if empty_streak >= 2:
            break

        page += 1

        if page >= max_pages:
            detail = (
                f"{scope}: hit the {max_pages}-page safety cap after "
                f"{len(records)} records. The walk was stopped, so this "
                f"result set may be incomplete."
            )
            if tracker:
                tracker.record_failure(scope, detail)
            print(f"    ! {detail}")
            break

        if sleep_time > 0:
            time.sleep(sleep_time)

    return records, total_elements, pages_fetched


# ---------------------------------------------------------------------------
# Text Utilities
# ---------------------------------------------------------------------------

def strip_html_tags(text: Optional[str]) -> Optional[str]:
    """Remove HTML tags, decode entities, and normalise whitespace.

    Also attempts base64 decoding for payloads that look like encoded HTML.
    """
    if not text:
        return text

    # Heuristic: long, space-free ASCII means likely base64-encoded HTML.
    if len(text) > 100 and " " not in text and text.isascii():
        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="ignore")
            if "<" in decoded and ">" in decoded:
                text = decoded
        except Exception:
            pass

    text = _RE_HTML_TAG.sub("", text)
    text = html.unescape(text)
    text = _RE_WHITESPACE.sub(" ", text).strip()
    return text


def _extract_team_name(app_profile: dict[str, Any]) -> Optional[str]:
    """Extract the team/BU name from an application profile."""
    bu = app_profile.get("business_unit")
    if isinstance(bu, dict):
        name = bu.get("name")
        if name and name != "Not Specified":
            return name

    teams = app_profile.get("teams", [])
    if isinstance(teams, list) and teams:
        first = teams[0]
        if isinstance(first, dict):
            return first.get("team_name")
    return None


# ---------------------------------------------------------------------------
# Finding Field Extractors
# ---------------------------------------------------------------------------

def _extract_cwe_id(details: dict[str, Any]) -> Optional[int]:
    cwe = details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("id")
    if isinstance(cwe, (int, float)):
        return int(cwe)
    return None


def _extract_cwe_name(details: dict[str, Any]) -> Optional[str]:
    cwe = details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("name")
    return details.get("finding_category") or details.get("flaw_name")


def _extract_cve_id(details: dict[str, Any]) -> Optional[str]:
    cve = details.get("cve")
    if isinstance(cve, dict):
        return cve.get("name")
    if isinstance(cve, str):
        return cve
    return None


def _extract_cvss(details: dict[str, Any]) -> Optional[float]:
    cve = details.get("cve")
    if isinstance(cve, dict):
        cvss3 = cve.get("cvss3")
        if isinstance(cvss3, dict):
            score = cvss3.get("score")
            if score is not None:
                return score
        return cve.get("cvss")
    return details.get("cvss")


_FILENAME_KEYS: dict[str, tuple[str, ...]] = {
    "STATIC": ("file_name", "file_path"),
    "DYNAMIC": ("path", "URL"),
    "MANUAL": ("location", "module"),
    "SCA": ("component_filename", "version"),
}


def _extract_filename(details: dict[str, Any], scan_type: str) -> Optional[str]:
    for key in _FILENAME_KEYS.get(scan_type, ()):
        val = details.get(key)
        if val:
            return val
    return None


def _extract_mitigation_comments(finding: dict[str, Any]) -> Optional[str]:
    """Build a pipe-delimited string from annotation comments.

    Requires include_annot=TRUE on the findings request, which this version
    sends by default. Without it the annotations node is absent and this
    always returned None.
    """
    annotations = finding.get("annotations") or []
    parts: list[str] = []
    for ann in annotations:
        comment = ann.get("comment")
        if comment:
            action = ann.get("action", "")
            parts.append(f"[{action}] {comment}" if action else comment)
    return " | ".join(parts) if parts else None


# ---------------------------------------------------------------------------
# Date Helpers
# ---------------------------------------------------------------------------

def _days_between(start_iso: Optional[str], end_iso: Optional[str]) -> Optional[int]:
    """Return the number of days between two ISO-8601 date strings, or None."""
    if not start_iso or not end_iso:
        return None
    try:
        s = dt.datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        e = dt.datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
        return (e - s).days
    except (ValueError, TypeError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Scan-URL Parsing
# ---------------------------------------------------------------------------

def _parse_scan_url_params(scan_url: str) -> Optional[tuple[int, str]]:
    """Parse ``'Prefix:a:b:12345:extra'`` into ``(12345, '12345:extra')``."""
    parts = scan_url.split(":")
    if len(parts) >= 4:
        try:
            build_id = int(parts[3])
            return build_id, ":".join(parts[3:])
        except (ValueError, IndexError):
            pass
    return None


# ---------------------------------------------------------------------------
# Veracode Deep-Link Generation
# ---------------------------------------------------------------------------

def _link_suffix(primary: str, secondary: Optional[str]) -> str:
    return f"{primary}:{secondary}" if secondary else f"{primary}:"


def _generate_veracode_link(
    app_guid: str,
    scan_type: str,
    details: Optional[dict[str, Any]],
    sandbox_guid: Optional[str] = None,
    finding_obj: Optional[dict[str, Any]] = None,
    app_id: Optional[str] = None,
    app_oid: Optional[str] = None,
) -> Optional[str]:
    """Build a platform deep-link appropriate for the scan type."""
    if not app_guid:
        return None
    base = ANALYSIS_CENTER_BASE

    if scan_type == "STATIC":
        return _link_static(base, app_guid, app_id, app_oid, sandbox_guid, finding_obj, details)
    if scan_type == "DYNAMIC":
        return _link_dynamic(base, app_guid, sandbox_guid, finding_obj)
    if scan_type == "MANUAL":
        return f"{base}#AnalyzeAppManualList:{_link_suffix(app_guid, sandbox_guid)}"
    if scan_type == "SCA":
        return _link_sca(base, app_guid, app_id, app_oid, sandbox_guid, finding_obj, details)
    return f"{base}#AnalyzeAppModuleList:{app_guid}:"


def _link_static(
    base: str, app_guid: str, app_id: Optional[str], app_oid: Optional[str],
    sandbox_guid: Optional[str], finding_obj: Optional[dict], details: Optional[dict],
) -> str:
    scan_params = None
    if finding_obj:
        # Prefer the params for the build the finding actually came from.
        scan_params = (
            finding_obj.get("_finding_scan_params")
            or finding_obj.get("_latest_scan_params")
        )
    if scan_params and app_oid and app_id:
        return f"{base}#ReviewResultsAllFlaws:{app_oid}:{app_id}:{scan_params}"

    build_id = (finding_obj or {}).get("build_id") or (details or {}).get("build_id")
    if build_id and app_oid and app_id:
        return f"{base}#ReviewResultsAllFlaws:{app_oid}:{app_id}:{build_id}"
    if app_oid and app_id:
        return f"{base}#AnalyzeAppModuleList:{app_oid}:{app_id}:"
    return f"{base}#AnalyzeAppModuleList:{_link_suffix(app_guid, sandbox_guid)}"


def _link_dynamic(
    base: str, app_guid: str, sandbox_guid: Optional[str], finding_obj: Optional[dict],
) -> str:
    if finding_obj:
        da_id = finding_obj.get("_dynamic_analysis_id")
        if da_id:
            return f"https://web.analysiscenter.veracode.com/was/#/analysis/{da_id}/scans"
        dast_url = finding_obj.get("_dast_scan_url")
        if dast_url:
            return f"{base}#{dast_url}"
    return f"{base}#AnalyzeAppDynamicList:{_link_suffix(app_guid, sandbox_guid)}"


def _link_sca(
    base: str, app_guid: str, app_id: Optional[str], app_oid: Optional[str],
    sandbox_guid: Optional[str], finding_obj: Optional[dict], details: Optional[dict],
) -> str:
    if details:
        metadata = details.get("metadata") or {}
        if str(metadata.get("sca_scan_mode", "")).upper() == "AGENT":
            ws = (
                details.get("workspace_guid") or details.get("workspace_id")
                or metadata.get("workspace_guid") or metadata.get("workspace_id")
            )
            pid = details.get("project_id") or metadata.get("project_id")
            if finding_obj:
                ws = ws or finding_obj.get("_sca_workspace_guid") or finding_obj.get("workspace_guid")
                pid = pid or finding_obj.get("_sca_project_id") or finding_obj.get("project_id")
            if ws and pid:
                return f"https://sca.analysiscenter.veracode.com/workspaces/{ws}/projects/{pid}/issues"
            return "https://sca.analysiscenter.veracode.com/workspaces"

    scan_params = (finding_obj or {}).get("_latest_scan_params")
    if scan_params and app_oid and app_id:
        return f"{base}#ReviewResultsSCA:{app_oid}:{app_id}:{scan_params}"
    if app_oid and app_id:
        return f"{base}#AnalyzeAppSourceComposition:{app_oid}:{app_id}:"
    return f"{base}#AnalyzeAppSourceComposition:{_link_suffix(app_guid, sandbox_guid)}"


# ---------------------------------------------------------------------------
# Finding Normalisation
# ---------------------------------------------------------------------------

def normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Normalise a raw API finding record into the common CSV schema."""
    app_profile = finding.get("_app_profile") or {}
    scan_type = finding.get("scan_type")
    original_scan_type = scan_type
    details = finding.get("finding_details") or {}

    # Refine scan-type label for display
    if scan_type == "SCA":
        if (details.get("metadata") or {}).get("sca_scan_mode") == "AGENT":
            scan_type = "SCA Agent"
    elif scan_type == "DYNAMIC":
        if finding.get("_dynamic_analysis_id"):
            scan_type = "Dynamic Analysis"
        elif finding.get("_dast_scan_url"):
            scan_type = "DAST"

    status_obj = finding.get("finding_status") or {}
    first_found = status_obj.get("first_found_date")
    status = status_obj.get("status")
    resolution_status = status_obj.get("resolution_status")

    fixed_date = None
    if status == "CLOSED" or resolution_status == "FIXED":
        fixed_date = status_obj.get("resolution_date") or status_obj.get("last_seen_date")

    cve_id = _extract_cve_id(details)
    flaw_name = _extract_cwe_name(details)
    severity = details.get("severity")

    vuln_title = None
    if scan_type in ("SCA", "SCA Agent"):
        vuln_title = cve_id or flaw_name

    app_guid = finding.get("_app_guid")
    app_id = finding.get("_app_id")
    app_oid = finding.get("_app_oid")

    return {
        "Application Name": finding.get("_app_name"),
        "Application ID": app_guid,
        "Sandbox Name": finding.get("_sandbox_name"),
        "Custom Severity Name": SEVERITY_LABEL.get(severity) if severity is not None else None,
        "CVE ID": cve_id,
        "Description": strip_html_tags(finding.get("description")),
        "Vulnerability Title": vuln_title,
        "CWE ID": _extract_cwe_id(details),
        "Flaw Name": flaw_name,
        "First Found Date": first_found,
        "Filename/Class": _extract_filename(details, original_scan_type),
        "Finding Status": status,
        "Fixed Date": fixed_date,
        "Team Name": _extract_team_name(app_profile),
        "Days to Resolve": _days_between(first_found, fixed_date),
        "Scan Type": scan_type,
        "CVSS": _extract_cvss(details),
        "Severity": severity,
        "Resolution Status": resolution_status,
        "Resolution": status_obj.get("resolution"),
        "Veracode Link": _generate_veracode_link(
            app_guid, original_scan_type, details,
            finding.get("_sandbox_guid"), finding, app_id, app_oid,
        ),
        "Mitigation Comments": _extract_mitigation_comments(finding),
        "Issue ID": finding.get("issue_id"),
        "Violates Policy": finding.get("violates_policy"),
    }


def normalize_iac_finding(
    finding: dict[str, Any],
    iac_record: dict[str, Any],
    app_name: str,
    app_guid: str,
    app_profile: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Normalise a detailed IaC finding into the common CSV schema."""
    sev_str = str(finding.get("severity", "unknown")).lower()
    sev_level, sev_label = IAC_SEVERITY_MAP.get(sev_str, (0, "Informational"))

    finding_id = finding.get("id", "")
    finding_type = finding.get("finding_type", "")
    title = strip_html_tags(finding.get("title", "") or finding.get("description", "IaC Misconfiguration"))
    description = strip_html_tags(finding.get("description", ""))
    suggested_fix = strip_html_tags(finding.get("suggested_fix", ""))
    rule_id = finding.get("rule_id", "")
    cvss = finding.get("cvss", "")

    raw_path = finding.get("filepath", [])
    file_path = raw_path[0] if isinstance(raw_path, list) and raw_path else (raw_path or "")
    start_line = finding.get("start_line", "")
    end_line = finding.get("end_line", "")

    full_desc = description or title
    if finding_id:
        full_desc = f"{finding_id}: {full_desc}"

    location = file_path
    if start_line and end_line:
        location += f" (Lines {start_line}-{end_line})"
    elif start_line:
        location += f" (Line {start_line})"

    scan_id = iac_record.get("scan_id", "")

    return {
        "Application Name": app_name,
        "Application ID": app_guid,
        "Sandbox Name": None,
        "Custom Severity Name": sev_label,
        "CVE ID": finding_id if finding_type == "vulnerability" else None,
        "Description": full_desc,
        "Vulnerability Title": finding_type.title() if finding_type else None,
        "CWE ID": rule_id or None,
        "Flaw Name": finding_id or title,
        "First Found Date": iac_record.get("scanned_at"),
        "Filename/Class": location or None,
        "Finding Status": "OPEN",
        "Fixed Date": None,
        "Team Name": _extract_team_name(app_profile) if app_profile else None,
        "Days to Resolve": None,
        "Scan Type": "IAC",
        "CVSS": cvss or None,
        "Severity": sev_level,
        "Resolution Status": None,
        "Resolution": None,
        "Veracode Link": (
            f"https://web.analysiscenter.veracode.com/app/container-iac-scans/{scan_id}/summary"
            if scan_id else None
        ),
        "Mitigation Comments": suggested_fix or None,
        "IAC File Path": file_path,
        "IAC Start Line": start_line or None,
        "IAC End Line": end_line or None,
        "Issue ID": finding_id or None,
        "Violates Policy": None,
    }


# ---------------------------------------------------------------------------
# API Fetchers
# ---------------------------------------------------------------------------

def get_applications(
    session: requests.Session,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
) -> list[dict[str, Any]]:
    """Fetch all applications via pagination.

    A failure here is fatal: a short application list silently drops every
    finding for every missing app, which was the single worst failure mode
    in the original script.
    """
    print("\n" + "=" * 70)
    print("  FETCHING APPLICATIONS")
    print("=" * 70)

    def _progress(page: int, batch: list, running: int, expected: Optional[int]) -> None:
        if page == 0 or (page + 1) % 5 == 0:
            exp = f"/{expected}" if expected else ""
            print(f"  Retrieved {running}{exp} applications so far...")

    apps, expected, pages = paginate(
        session, APPLICATIONS_URL, "applications",
        scope="applications",
        rate_limiter=rate_limiter,
        tracker=tracker,
        page_size=DEFAULT_PAGE_SIZE,
        timeout=60,
        on_page=_progress,
    )

    if expected is not None and expected != len(apps):
        tracker.record_mismatch("applications", expected, len(apps))
        print(f"  ! COUNT MISMATCH: API reported {expected}, retrieved {len(apps)}")

    print(f"\n  Total applications found: {len(apps)} "
          f"(expected {expected if expected is not None else 'unreported'}, "
          f"{pages} pages)\n")
    return apps


def get_sandboxes(
    session: requests.Session,
    app_guid: str,
    app_name: str,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
) -> list[dict[str, Any]]:
    """Return development sandboxes for an application.

    Now paginated. The original made a single unparameterised GET, so any
    application with more sandboxes than one default page lost the rest,
    and with them every finding in those sandboxes.
    """
    url = SANDBOXES_URL_TEMPLATE.format(app_guid=app_guid)
    try:
        sandboxes, expected, _ = paginate(
            session, url, "sandboxes",
            scope=f"sandboxes[{app_name}]",
            rate_limiter=rate_limiter,
            tracker=tracker,
            page_size=DEFAULT_PAGE_SIZE,
            timeout=60,
        )
    except FetchError as exc:
        tracker.record_failure(f"sandboxes[{app_name}]", str(exc))
        print(f"    FAILED to fetch sandboxes for {app_name}: {exc}")
        return []

    if expected is not None and expected != len(sandboxes):
        tracker.record_mismatch(f"sandboxes[{app_name}]", expected, len(sandboxes))
    return sandboxes


def get_sca_workspaces(
    session: requests.Session,
    sleep_time: float,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
) -> dict[str, dict[str, str]]:
    """Fetch SCA workspaces/projects.

    Returns a lookup keyed by lower-cased project name and 'guid:<app_guid>'.
    This map only drives deep-link construction; it never affects which
    findings are retrieved.
    """
    ws_map: dict[str, dict[str, str]] = {}
    try:
        all_ws, _, _ = paginate(
            session, f"{SCA_API_BASE}/workspaces", "workspaces",
            scope="sca-workspaces",
            rate_limiter=rate_limiter,
            tracker=tracker,
            page_size=DEFAULT_PAGE_SIZE,
            timeout=60,
            sleep_time=sleep_time,
        )
    except FetchError as exc:
        tracker.record_failure("sca-workspaces", str(exc))
        print(f"    FAILED to fetch SCA workspaces: {exc}")
        return ws_map

    print(f"  Fetched {len(all_ws)} SCA workspaces")

    total_proj = 0
    name_collisions = 0
    for workspace in all_ws:
        ws_id = workspace.get("id")
        ws_site = workspace.get("site_id")
        if not ws_id:
            continue
        try:
            projects, _, _ = paginate(
                session, f"{SCA_API_BASE}/workspaces/{ws_id}/projects", "projects",
                scope=f"sca-projects[{ws_id}]",
                rate_limiter=rate_limiter,
                tracker=tracker,
                page_size=DEFAULT_PAGE_SIZE,
                timeout=60,
                sleep_time=sleep_time,
            )
        except FetchError as exc:
            tracker.record_failure(f"sca-projects[{ws_id}]", str(exc))
            print(f"    FAILED to fetch SCA projects for workspace {ws_id}: {exc}")
            continue

        for proj in projects:
            ps = proj.get("site_id")
            pn = proj.get("name", "")
            lg = (proj.get("linked_application") or {}).get("guid")
            if ps and ws_site:
                mapping = {"workspace_guid": ws_site, "project_id": ps, "project_name": pn}
                key = pn.lower()
                if key in ws_map and ws_map[key] != mapping:
                    name_collisions += 1
                ws_map[key] = mapping
                if lg:
                    ws_map[f"guid:{lg}"] = mapping
                total_proj += 1

    print(f"  Fetched {total_proj} total SCA projects across all workspaces")
    if name_collisions:
        print(f"  Note: {name_collisions} duplicate project names across workspaces "
              f"(affects SCA deep links only, not finding counts)")
    return ws_map


def get_dynamic_analyses(
    session: requests.Session,
    sleep_time: float,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch Dynamic Analysis metadata keyed by linked application GUID.

    Both the analyses list and each analysis's scan list are now paginated.
    """
    da_map: dict[str, list[dict]] = {}
    try:
        analyses, _, _ = paginate(
            session, DYNAMIC_ANALYSES_URL, "analyses",
            scope="dynamic-analyses",
            rate_limiter=rate_limiter,
            tracker=tracker,
            page_size=DEFAULT_PAGE_SIZE,
            timeout=60,
            sleep_time=sleep_time,
        )
    except FetchError as exc:
        tracker.record_failure("dynamic-analyses", str(exc))
        print(f"    FAILED to fetch Dynamic Analyses: {exc}")
        return da_map

    for analysis in analyses:
        a_id = analysis.get("analysis_id")
        if not a_id:
            continue
        try:
            scans, _, _ = paginate(
                session, f"{DYNAMIC_ANALYSES_URL}/{a_id}/scans", "scans",
                scope=f"dynamic-analysis-scans[{a_id}]",
                rate_limiter=rate_limiter,
                tracker=tracker,
                page_size=DEFAULT_PAGE_SIZE,
                timeout=60,
                sleep_time=sleep_time,
            )
        except FetchError as exc:
            tracker.record_failure(f"dynamic-analysis-scans[{a_id}]", str(exc))
            continue

        for scan in scans:
            guid = scan.get("linked_platform_app_uuid")
            if guid:
                da_map.setdefault(guid, []).append({
                    "analysis_id": a_id,
                    "analysis_name": analysis.get("name"),
                })
    return da_map


# ---------------------------------------------------------------------------
# Findings Fetchers
# ---------------------------------------------------------------------------

def _fetch_findings_context(
    session: requests.Session,
    app_guid: str,
    app_name: str,
    app_profile: dict[str, Any],
    scan_type: Optional[str],
    filters: dict[str, Any],
    sleep_time: float,
    sandbox_guid: Optional[str],
    sandbox_name: Optional[str],
    app_id: Optional[str],
    app_oid: Optional[str],
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    page_size: int,
    include_annotations: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Paginate all findings for one app / sandbox / scan-type combination.

    Returns ``(findings, reconciliation_row)``. Unlike the original, a mid-walk
    failure is recorded and surfaced rather than silently truncating the walk
    and returning as if the app were fully processed.
    """
    url = FINDINGS_URL_TEMPLATE.format(app_guid=app_guid)

    params: dict[str, Any] = {}
    if sandbox_guid:
        params["context"] = sandbox_guid
    if scan_type:
        params["scan_type"] = scan_type
    if filters.get("cwe"):
        params["cwe"] = filters["cwe"]
    for key in ("severity", "severity_gte"):
        if filters.get(key) is not None:
            params[key] = filters[key]
    if filters.get("violates_policy"):
        params["violates_policy"] = "TRUE"
    if include_annotations:
        # Without this the annotations node is absent and Mitigation Comments
        # is always blank.
        params["include_annot"] = "TRUE"

    # NOTE: 'status' is deliberately NOT sent. It is not a documented Findings
    # API query parameter; sending it silently returns unfiltered data. The
    # filter is applied client-side by the caller instead.

    context_label = f"sandbox:{sandbox_name}" if sandbox_guid else "policy"
    scope = f"findings[{app_name}|{context_label}|{scan_type or 'ALL'}]"

    recon: dict[str, Any] = {
        "Application Name": app_name,
        "Application GUID": app_guid,
        "Context": context_label,
        "Scan Type Requested": scan_type or "ALL",
        "Expected (API total_elements)": "",
        "Retrieved": 0,
        "Pages Fetched": 0,
        "Status": "OK",
        "Detail": "",
    }

    try:
        findings, expected, pages = paginate(
            session, url, "findings",
            scope=scope,
            rate_limiter=rate_limiter,
            tracker=tracker,
            params=params,
            page_size=page_size,
            timeout=180,
            sleep_time=sleep_time,
        )
    except FetchError as exc:
        tracker.record_failure(scope, str(exc))
        tracker.record_page(ok=False)
        recon["Status"] = "FAILED"
        recon["Detail"] = str(exc)[:300]
        print(f"    FAILED {scope}: {exc}")
        return [], recon

    for finding in findings:
        finding["_app_name"] = app_name
        finding["_app_guid"] = app_guid
        finding["_app_profile"] = app_profile
        finding["_sandbox_name"] = sandbox_name if sandbox_guid else None
        finding["_sandbox_guid"] = sandbox_guid
        finding["_app_id"] = app_id
        finding["_app_oid"] = app_oid

    recon["Expected (API total_elements)"] = "" if expected is None else expected
    recon["Retrieved"] = len(findings)
    recon["Pages Fetched"] = pages

    if expected is not None and expected != len(findings):
        tracker.record_mismatch(scope, expected, len(findings))
        recon["Status"] = "MISMATCH"
        recon["Detail"] = f"API reported {expected}, retrieved {len(findings)}"
        print(f"    ! MISMATCH {scope}: expected {expected}, got {len(findings)}")

    if findings:
        print(f"    [{context_label}|{scan_type or 'ALL'}] {len(findings)} findings "
              f"across {pages} page(s)")

    return findings, recon


def _get_all_findings_for_app(
    session: requests.Session,
    app_guid: str,
    app_name: str,
    app_profile: dict[str, Any],
    filters: dict[str, Any],
    sleep_time: float,
    include_sandboxes: bool,
    app_id: Optional[str],
    app_oid: Optional[str],
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    page_size: int,
    include_annotations: bool,
    combine_scan_types: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch findings for the policy scan plus, optionally, every sandbox.

    SCA must be requested on its own: Veracode documents that combining SCA
    with other scan types is not supported.
    """
    all_findings: list[dict] = []
    recon_rows: list[dict] = []

    requested = _parse_requested_scan_types(filters.get("scan_type"))
    if requested:
        fetch_sca = "SCA" in requested
        non_sca = [t for t in requested if t in NON_SCA_SCAN_TYPES]
    else:
        fetch_sca = True
        non_sca = list(NON_SCA_SCAN_TYPES)

    # Only single scan_type values are documented. Requesting them one at a
    # time is a few extra calls per app but removes the risk that a
    # comma-joined value is partially honoured or ignored outright.
    if combine_scan_types:
        non_sca_batches = [",".join(non_sca)] if non_sca else []
    else:
        non_sca_batches = list(non_sca)

    contexts: list[tuple[Optional[str], Optional[str]]] = [(None, None)]

    if include_sandboxes:
        sbs = get_sandboxes(session, app_guid, app_name, rate_limiter, tracker)
        if sbs:
            print(f"    Found {len(sbs)} sandbox(es)")
        for sb in sbs:
            sg = sb.get("guid")
            if sg:
                contexts.append((sg, sb.get("name", sg)))

    for ctx_guid, ctx_name in contexts:
        for st in non_sca_batches:
            findings, recon = _fetch_findings_context(
                session, app_guid, app_name, app_profile, st, filters,
                sleep_time, ctx_guid, ctx_name, app_id, app_oid,
                rate_limiter, tracker, page_size, include_annotations,
            )
            all_findings.extend(findings)
            recon_rows.append(recon)

        if fetch_sca:
            findings, recon = _fetch_findings_context(
                session, app_guid, app_name, app_profile, "SCA", filters,
                sleep_time, ctx_guid, ctx_name, app_id, app_oid,
                rate_limiter, tracker, page_size, include_annotations,
            )
            all_findings.extend(findings)
            recon_rows.append(recon)

    return all_findings, recon_rows


# ---------------------------------------------------------------------------
# Per-Application Worker (thread pool)
# ---------------------------------------------------------------------------

def _process_application(
    app: dict[str, Any],
    idx: int,
    total: int,
    filters: dict[str, Any],
    sleep_time: float,
    include_sandboxes: bool,
    sca_map: dict[str, dict[str, str]],
    da_map: dict[str, list[dict[str, Any]]],
    rate_limiter: RateLimiter,
    tracker: FailureTracker,
    page_size: int,
    include_annotations: bool,
    combine_scan_types: bool,
    ca_cert: Optional[str] = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch and enrich findings for one application (thread worker)."""
    session = create_session(ca_cert=ca_cert)
    profile = app.get("profile") or {}
    app_guid = app.get("guid")
    app_name = profile.get("name", "Unknown")

    try:
        app_id = app.get("id")
        app_oid = app.get("oid") or app.get("alt_org_id")

        # ---- Single-pass scan-URL parsing ----
        static_params_by_build: dict[int, str] = {}
        dast_url_by_build: dict[int, str] = {}
        latest_scan_params: Optional[str] = None

        for scan in app.get("scans", []):
            scan_url = scan.get("scan_url", "")
            if not scan_url:
                continue
            stype = scan.get("scan_type")
            if stype == "STATIC":
                parsed = _parse_scan_url_params(scan_url)
                if parsed:
                    static_params_by_build[parsed[0]] = parsed[1]
                    if latest_scan_params is None:  # first entry is latest
                        latest_scan_params = parsed[1]
            elif stype == "DYNAMIC" and scan_url.startswith("DynamicParamsView:"):
                parsed = _parse_scan_url_params(scan_url)
                if parsed:
                    dast_url_by_build[parsed[0]] = scan_url

        print(f"  [{idx}/{total}] {app_name} ({app_guid})")

        findings, recon_rows = _get_all_findings_for_app(
            session, app_guid, app_name, profile, filters,
            sleep_time, include_sandboxes, app_id, app_oid, rate_limiter,
            tracker, page_size, include_annotations, combine_scan_types,
        )

        # ---- Enrich findings ----
        for finding in findings:
            finding["_latest_scan_params"] = latest_scan_params
            ftype = finding.get("scan_type")
            build_id = finding.get("build_id")

            if ftype == "STATIC" and build_id and build_id in static_params_by_build:
                finding["_finding_scan_params"] = static_params_by_build[build_id]

            elif ftype == "DYNAMIC":
                if build_id and build_id in dast_url_by_build:
                    finding["_dast_scan_url"] = dast_url_by_build[build_id]
                da_list = da_map.get(app_guid)
                if da_list:
                    finding["_dynamic_analysis_id"] = da_list[0].get("analysis_id")

            elif ftype == "SCA":
                meta = (finding.get("finding_details") or {}).get("metadata") or {}
                if meta.get("sca_scan_mode") == "AGENT":
                    mapping = sca_map.get(f"guid:{app_guid}") or sca_map.get(app_name.lower())
                    if mapping:
                        finding["_sca_workspace_guid"] = mapping["workspace_guid"]
                        finding["_sca_project_id"] = mapping["project_id"]

        print(f"    Total for {app_name}: {len(findings)}\n")
        return findings, recon_rows

    except Exception as exc:
        # Anything reaching here is unexpected; record it so the run cannot
        # report success.
        tracker.record_failure(f"application[{app_name}]", f"{type(exc).__name__}: {exc}")
        print(f"    UNEXPECTED ERROR processing {app_name}: {exc}\n")
        return [], [{
            "Application Name": app_name,
            "Application GUID": app_guid,
            "Context": "n/a",
            "Scan Type Requested": "n/a",
            "Expected (API total_elements)": "",
            "Retrieved": 0,
            "Pages Fetched": 0,
            "Status": "FAILED",
            "Detail": f"{type(exc).__name__}: {exc}"[:300],
        }]
    finally:
        session.close()


# ---------------------------------------------------------------------------
# IaC Live Fetching (principal token auth)
# ---------------------------------------------------------------------------

def _get_principal_token() -> str:
    """Get a session token via HMAC-authenticated principal API call."""
    try:
        principal = APIHelper()._rest_request("api/authn/v2/principal", "GET")
    except Exception as exc:
        raise RuntimeError(f"Failed to retrieve principal token: {exc}") from exc

    if not isinstance(principal, dict) or "token" not in principal:
        raise RuntimeError(
            f"Unexpected principal response type: {type(principal).__name__}"
        )
    return principal["token"]


def _iac_auth_header(token: str) -> dict[str, str]:
    """Build the Authorization header for IaC/Container Security API calls."""
    return {"Authorization": f"{IAC_AUTH_TOKEN_PREFIX}{token}"}


class IacTokenProvider:
    """Holds the IaC principal token and re-mints it on demand.

    The token was previously fetched once and reused for the whole IaC
    phase, which begins only after the findings phase. On a large tenant
    that can be hours later, so expiry is expected rather than exceptional.
    Refresh is serialised and de-duplicated: concurrent workers hitting 401
    at the same time trigger exactly one refresh between them.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._generation = 0
        self.refreshes = 0

    def get(self) -> str:
        with self._lock:
            if self._token is None:
                self._token = _get_principal_token()
                self._generation += 1
            return self._token

    def headers(self) -> dict[str, str]:
        return _iac_auth_header(self.get())

    def refresh(self) -> dict[str, str]:
        """Mint a new token and return replacement headers."""
        with self._lock:
            seen = self._generation
            # Another thread may have refreshed while this one waited.
            if seen == self._generation:
                self._token = _get_principal_token()
                self._generation += 1
                self.refreshes += 1
            return _iac_auth_header(self._token or "")


def _paginate_iac(
    session: requests.Session,
    url: str,
    tokens: "IacTokenProvider",
    records_key: str,
    *,
    scope: str,
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    extra_params: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Paginate an IaC/Container Security collection with retries.

    This API uses ``pagination.total_pages`` and a ``limit`` parameter rather
    than the HAL shape used elsewhere.
    """
    all_records: list[dict] = []
    page = 0
    empty_streak = 0

    while True:
        params = dict(extra_params or {})
        params.update({"page": page, "limit": IAC_MAX_RECORDS})

        resp = request_with_retry(
            session, url,
            scope=f"{scope} page {page}",
            rate_limiter=rate_limiter,
            tracker=tracker,
            headers=tokens.headers(),
            params=params,
            timeout=90,
            passthrough_statuses=(404,),
            auth_refresh=tokens.refresh,
        )
        if resp.status_code == 404:
            break

        try:
            data = resp.json()
        except ValueError as exc:
            raise FetchError(f"{scope} page {page}: invalid JSON ({exc})") from exc

        records = data.get(records_key, []) or []
        all_records.extend(records)
        empty_streak = 0 if records else empty_streak + 1

        total_pages = (data.get("pagination") or {}).get("total_pages", 1) or 1
        if page >= total_pages - 1 or empty_streak >= 2:
            break

        page += 1
        if page >= MAX_PAGES_SAFETY_CAP:
            detail = (f"{scope}: hit the {MAX_PAGES_SAFETY_CAP}-page safety cap "
                      f"after {len(all_records)} records; result may be incomplete.")
            tracker.record_failure(scope, detail)
            print(f"    ! {detail}")
            break

    return all_records


def _fetch_iac_scans(
    session: requests.Session,
    tokens: "IacTokenProvider",
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    filter_apps: Optional[set[str]] = None,
) -> list[dict[str, Any]]:
    """Fetch the IaC scan list using principal token auth."""
    print("  Fetching IaC scan list...")
    try:
        all_records = _paginate_iac(
            session, IAC_SCANS_URL, tokens, "records",
            scope="iac-scans",
            rate_limiter=rate_limiter,
            tracker=tracker,
        )
    except FetchError as exc:
        tracker.record_failure("iac-scans", str(exc))
        print(f"  FAILED to fetch IaC scans: {exc}")
        return []

    if filter_apps:
        filter_lc = {n.lower() for n in filter_apps}
        all_records = [
            r for r in all_records
            if str(r.get("asset_name", "")).lower() in filter_lc
        ]
        print(f"  Filtered to {len(all_records)} scans matching specified apps")

    print(f"  Found {len(all_records)} IaC scans\n")
    return all_records


def _process_iac_scan(
    record: dict[str, Any],
    idx: int,
    total: int,
    tokens: "IacTokenProvider",
    rate_limiter: Optional[RateLimiter],
    tracker: FailureTracker,
    ca_cert: Optional[str] = None,
) -> dict[str, Any]:
    """Fetch detailed findings for one IaC scan (thread worker)."""
    asset_name = record.get("asset_name", "Unknown")
    scan_id = record.get("scan_id")

    if not scan_id:
        tracker.record_failure(f"iac-scan[{asset_name}]", "record has no scan_id")
        return record

    session = create_session(ca_cert=ca_cert, use_hmac=False)
    try:
        findings = _paginate_iac(
            session, IAC_FINDINGS_URL_TEMPLATE.format(scan_id=scan_id), tokens, "findings",
            scope=f"iac-findings[{asset_name}:{scan_id}]",
            rate_limiter=rate_limiter,
            tracker=tracker,
            extra_params={"sort": "severity", "direction": "desc"},
        )
    except FetchError as exc:
        tracker.record_failure(f"iac-findings[{asset_name}:{scan_id}]", str(exc))
        print(f"    FAILED IaC findings for {asset_name} (scan {scan_id}): {exc}")
        findings = []
    finally:
        session.close()

    detailed_record = record.copy()
    detailed_record["detailed_findings"] = findings
    print(f"    [{idx}/{total}] {asset_name} (scan {scan_id}): {len(findings)} findings")
    return detailed_record


def _fetch_iac_data_live(
    rate_limiter: RateLimiter,
    tracker: FailureTracker,
    max_workers: int = 5,
    filter_apps: Optional[set[str]] = None,
    ca_cert: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Fetch IaC scan data live via principal token auth."""
    print("  Obtaining principal token via HMAC auth...")
    tokens = IacTokenProvider()
    try:
        tokens.get()
        print("  Principal token obtained (auto-refreshes on 401)\n")
    except RuntimeError as exc:
        tracker.record_failure("iac-principal-token", str(exc))
        print(f"  {exc}")
        return []

    session = create_session(ca_cert=ca_cert, use_hmac=False)
    try:
        records = _fetch_iac_scans(session, tokens, rate_limiter, tracker, filter_apps)
    finally:
        session.close()

    if not records:
        return []

    print(f"  Fetching detailed findings for {len(records)} scans...\n")
    detailed_records: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_record = {
            executor.submit(
                _process_iac_scan,
                record=rec, idx=idx, total=len(records),
                tokens=tokens, rate_limiter=rate_limiter, tracker=tracker,
                ca_cert=ca_cert,
            ): rec
            for idx, rec in enumerate(records, 1)
        }
        for future in as_completed(future_to_record):
            rec = future_to_record[future]
            try:
                detailed_records.append(future.result())
            except Exception as exc:
                name = rec.get("asset_name", "Unknown")
                tracker.record_failure(f"iac-scan[{name}]", f"{type(exc).__name__}: {exc}")
                print(f"    ERROR processing {name}: {exc}")

    total_findings = sum(len(r.get("detailed_findings", [])) for r in detailed_records)
    print(f"\n  Fetched {len(detailed_records)} IaC scans with {total_findings} total findings")
    return detailed_records


# ---------------------------------------------------------------------------
# Post-processing
# ---------------------------------------------------------------------------

def _finding_key(row: dict[str, Any]) -> tuple:
    """Identity key for duplicate detection.

    A finding is uniquely identified by its issue ID within an application
    and context. Two different sandboxes legitimately report the same issue
    ID, so the context is part of the key.
    """
    return (
        row.get("_app_guid"),
        row.get("_sandbox_guid"),
        row.get("scan_type"),
        row.get("issue_id"),
    )


def analyse_duplicates(raw_findings: list[dict]) -> tuple[int, list[tuple]]:
    """Count exact duplicate finding identities. Purely diagnostic."""
    keys = [_finding_key(f) for f in raw_findings if isinstance(f, dict) and "issue_id" in f]
    counts = CollCounter(keys)
    dupes = [(k, c) for k, c in counts.items() if c > 1]
    total_extra = sum(c - 1 for _, c in dupes)
    return total_extra, dupes[:20]


def apply_status_filter(rows: list[dict], status: Optional[str]) -> list[dict]:
    """Apply the status filter client-side.

    'status' is not a documented Findings API query parameter, so filtering
    server-side was unreliable. This filters the normalised rows instead.
    """
    if not status:
        return rows
    want = status.upper()
    return [r for r in rows if str(r.get("Finding Status", "")).upper() == want]


def _row_passes_status(row: dict, status: Optional[str]) -> bool:
    """Single-row form of the status filter, for the streaming path."""
    if not status:
        return True
    return str(row.get("Finding Status", "")).upper() == status.upper()


def safe_normalize(
    finding: dict[str, Any],
    tracker: FailureTracker,
) -> dict[str, Any]:
    """Normalise one finding, never raising.

    The previous implementation normalised inside a list comprehension, so a
    single API shape drift (for example ``finding_status`` arriving as a
    string instead of an object) raised and destroyed the ENTIRE export -
    every finding lost, no CSV written at all. Across hundreds of thousands
    of records the chance of zero anomalies is not a safe bet.

    A finding that cannot be normalised is never silently dropped. A salvage
    row is emitted carrying whatever identifying fields can be read directly,
    with the reason in ``Export Notes``, and the failure is registered so the
    run reports INCOMPLETE.
    """
    if "Application Name" in finding:
        return finding  # already-normalised (IaC) row
    try:
        return normalize_finding(finding)
    except Exception as exc:
        scope = f"normalize[{finding.get('_app_name', '?')}]"
        detail = f"issue_id={finding.get('issue_id', '?')}: {type(exc).__name__}: {exc}"
        tracker.record_failure(scope, detail)

        salvage = {k: None for k in CSV_FIELDNAMES}
        for key, src in (
            ("Application Name", "_app_name"), ("Application ID", "_app_guid"),
            ("Sandbox Name", "_sandbox_name"), ("Issue ID", "issue_id"),
            ("Scan Type", "scan_type"), ("Violates Policy", "violates_policy"),
        ):
            try:
                salvage[key] = finding.get(src)
            except Exception:
                pass
        salvage["Export Notes"] = f"NORMALIZATION_FAILED: {type(exc).__name__}: {exc}"[:400]
        return salvage


def _sort_key(row: dict[str, Any]) -> tuple:
    """Deterministic ordering key.

    Without this, ``as_completed`` produced a different row order on every
    run, so two exports of an unchanged tenant could not be diffed.
    """
    def s(v: Any) -> str:
        return "" if v is None else str(v)
    return (s(row.get("Application Name")), s(row.get("Sandbox Name")),
            s(row.get("Scan Type")), s(row.get("Issue ID")))


class StreamingExporter:
    """Writes findings to disk incrementally, publishing atomically.

    Three defects are addressed here.

    Memory: the previous design accumulated every raw finding in one list,
    built a second full list during normalisation, and serialised a third
    copy via ``json.dump(..., indent=2)``. At a measured ~1.8 KB retained per
    raw finding that is roughly 4 GB for 700k findings and over 11 GB for two
    million, which will not survive a large tenant. Rows are now written per
    application and released.

    Atomicity: output went straight to the destination path, so a crash left
    a truncated CSV with a valid header AND destroyed the previous good
    export. Everything is written to temp files and moved into place with
    ``os.replace`` only after the run finishes. If the process dies, the
    destination is untouched and the temp files remain for inspection.

    Ordering: rows within an application are sorted, and applications are
    consumed in submission order, so the output is reproducible.
    """

    def __init__(
        self,
        csv_path: str,
        recon_path: str,
        tracker: FailureTracker,
        status_filter: Optional[str] = None,
        raw_json_path: Optional[str] = None,
        dedup: bool = False,
        excel_bom: bool = False,
    ) -> None:
        self.csv_path = csv_path
        self.recon_path = recon_path
        self.tracker = tracker
        self.status_filter = status_filter
        self.dedup = dedup
        # Plain utf-8 by default. utf-8-sig makes Excel happy but prefixes a
        # BOM to the first header cell, which silently breaks csv.DictReader
        # and any downstream keying on "Application Name".
        self._encoding = "utf-8-sig" if excel_bom else "utf-8"

        suffix = f".tmp.{os.getpid()}"
        self._csv_tmp = csv_path + suffix
        self._recon_tmp = recon_path + suffix
        self._raw_tmp = (raw_json_path + suffix) if raw_json_path else None
        self.raw_json_path = raw_json_path

        self.rows_written = 0
        self.rows_filtered_out = 0
        self.duplicates_seen = 0
        self.duplicates_removed = 0
        self.by_scan_type: CollCounter = CollCounter()
        self.recon_written = 0
        self._duplicate_samples: list[tuple] = []
        self._lock = threading.Lock()
        self._closed = False

    def __enter__(self) -> "StreamingExporter":
        self._csv_fh = open(self._csv_tmp, "w", encoding=self._encoding, newline="")
        self._csv_writer = csv.DictWriter(
            self._csv_fh, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
        self._csv_writer.writeheader()

        self._recon_fh = open(self._recon_tmp, "w", encoding=self._encoding, newline="")
        self._recon_writer = csv.DictWriter(
            self._recon_fh, fieldnames=RECON_FIELDNAMES, extrasaction="ignore")
        self._recon_writer.writeheader()

        self._raw_fh = (open(self._raw_tmp, "w", encoding="utf-8")
                        if self._raw_tmp else None)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close(publish=exc_type is None)

    def write_batch(self, raw_findings: list[dict[str, Any]]) -> None:
        """Normalise, filter, sort and write one application's findings.

        Duplicate detection is exact despite streaming: a duplicate can only
        arise within one (app, sandbox, scan_type), and all of an
        application's contexts are fetched by a single worker, so the whole
        equivalence class is present in this batch.
        """
        if not raw_findings:
            return

        with self._lock:
            if self._raw_fh:
                # JSON Lines, not one giant indented array: constant memory
                # and the file stays readable if the run is interrupted.
                for f in raw_findings:
                    self._raw_fh.write(json.dumps(f, default=str) + "\n")

            seen: set = set()
            batch: list[dict] = []
            for finding in raw_findings:
                if isinstance(finding, dict) and "issue_id" in finding:
                    key = _finding_key(finding)
                    if key in seen:
                        self.duplicates_seen += 1
                        if len(self._duplicate_samples) < 20:
                            self._duplicate_samples.append(key)
                        if self.dedup:
                            self.duplicates_removed += 1
                            continue
                    seen.add(key)

                row = safe_normalize(finding, self.tracker)
                if not _row_passes_status(row, self.status_filter):
                    self.rows_filtered_out += 1
                    continue
                batch.append(row)

            batch.sort(key=_sort_key)
            for row in batch:
                self._csv_writer.writerow(row)
                self.by_scan_type[str(row.get("Scan Type"))] += 1
            self.rows_written += len(batch)

    def write_recon(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        with self._lock:
            for row in rows:
                self._recon_writer.writerow(row)
            self.recon_written += len(rows)

    def close(self, publish: bool = True) -> None:
        """Flush, fsync and atomically move temp files into place."""
        if self._closed:
            return
        self._closed = True

        for fh in (self._csv_fh, self._recon_fh, self._raw_fh):
            if fh:
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
                fh.close()

        if not publish:
            print(f"\n  Export aborted. Partial data left at:\n"
                  f"    {self._csv_tmp}\n"
                  f"  The previous {self.csv_path} was NOT overwritten.")
            return

        for tmp, final in ((self._csv_tmp, self.csv_path),
                           (self._recon_tmp, self.recon_path),
                           (self._raw_tmp, self.raw_json_path)):
            if tmp and final:
                os.replace(tmp, final)  # atomic on POSIX and Windows

    @property
    def duplicate_samples(self) -> list[tuple]:
        return self._duplicate_samples


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Export Veracode FINDINGS data via Findings REST API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Notes:\n"
            "  The Findings API returns the LATEST policy scan for each application.\n"
            "  Sandbox findings require --include-sandbox.\n"
            "  SCA agent findings appear only when the agent project is linked to\n"
            "  an application profile. For tenant-wide extraction, consider the\n"
            "  Reporting API (FINDINGS report) instead of this per-app fan-out.\n"
        ),
    )
    p.add_argument("--output", default="veracode_findings_api.csv",
                   help="Output CSV filename (default: veracode_findings_api.csv).")
    p.add_argument("--app-name",
                   help="Comma-separated application name(s) to filter.")
    p.add_argument("--app-guid",
                   help="Specific application GUID to process.")
    p.add_argument("--scan-type",
                   help="Comma-separated scan types: STATIC, DYNAMIC, MANUAL, SCA, IAC.")
    p.add_argument("--severity", type=int, choices=range(6), metavar="0-5",
                   help="Exact severity filter (0-5).")
    p.add_argument("--severity-gte", type=int, choices=range(6), metavar="0-5",
                   help="Minimum severity filter (0-5).")
    p.add_argument("--cwe",
                   help="CWE ID filter (single or comma-separated).")
    p.add_argument("--status", choices=["OPEN", "CLOSED"],
                   help="Finding status filter (applied client-side).")
    p.add_argument("--violates-policy", action="store_true", default=False,
                   help="Only return findings that do not pass policy.")
    p.add_argument("--include-sandbox", action="store_true", default=False,
                   help="Include sandbox findings (default: policy scan only).")
    p.add_argument("--no-annotations", action="store_true", default=False,
                   help="Do not request annotations (Mitigation Comments will be blank).")
    p.add_argument("--combine-scan-types", action="store_true", default=False,
                   help="Request STATIC,DYNAMIC,MANUAL in one call instead of "
                        "separately. Fewer calls, but only single scan_type values "
                        "are documented.")
    p.add_argument("--excel-bom", action="store_true", default=False,
                   help="Write a UTF-8 BOM so Excel opens non-ASCII correctly. "
                        "Off by default because the BOM breaks csv.DictReader.")
    p.add_argument("--raw-json", action="store_true", default=False,
                   help="Also write raw API findings as JSON Lines. Off by "
                        "default: on a large tenant this file is enormous.")
    p.add_argument("--dedup", action="store_true", default=False,
                   help="Drop duplicate finding identities. Duplicates are always "
                        "reported regardless of this flag.")
    p.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE,
                   help=f"Findings page size (default: {DEFAULT_PAGE_SIZE}).")
    p.add_argument("--sleep", type=float, default=0.0,
                   help="Extra sleep between API pages (default: 0.0; the rate "
                        "limiter already paces requests).")
    p.add_argument("--max-workers", type=int, default=5,
                   help="Concurrent threads (default: 5).")
    p.add_argument("--rate-limit", type=float, default=3.5,
                   help="Max API requests/second (default: 3.5 = 210/min, under "
                        "Veracode's 250/min guidance).")
    p.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS,
                   help=f"Retry attempts per request (default: {DEFAULT_MAX_ATTEMPTS}).")
    p.add_argument("--max-apps", type=int,
                   help="Limit apps processed (testing).")
    p.add_argument("--ca-cert",
                   help="Path to custom CA certificate bundle (.pem).")
    p.add_argument("--ignore-failures", action="store_true", default=False,
                   help="Exit 0 even when requests failed. Not recommended.")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = _parse_args()

    global DEFAULT_MAX_ATTEMPTS  # noqa: PLW0603
    DEFAULT_MAX_ATTEMPTS = max(1, args.max_attempts)

    rate_limiter = RateLimiter(requests_per_second=args.rate_limit)
    tracker = FailureTracker()

    if args.rate_limit > SAFE_RPS:
        print(f"\n  WARNING: --rate-limit {args.rate_limit}/s is "
              f"{args.rate_limit * 60:.0f} req/min. Veracode guidance is to stay "
              f"under 250 req/min. Expect 429s.\n")

    # --- Build filter dict ---
    filters: dict[str, Any] = {}
    if args.scan_type:
        filters["scan_type"] = args.scan_type
    if args.severity is not None:
        filters["severity"] = args.severity
    if args.severity_gte is not None:
        filters["severity_gte"] = args.severity_gte
    if args.cwe:
        filters["cwe"] = args.cwe
    if args.violates_policy:
        filters["violates_policy"] = True

    # --- Scan-type routing ---
    requested_types = _parse_requested_scan_types(args.scan_type)
    if requested_types:
        unknown = set(requested_types) - VALID_SCAN_TYPES
        if unknown:
            print(f"ERROR: Invalid scan type(s): {', '.join(sorted(unknown))}")
            print(f"  Valid values: {', '.join(sorted(VALID_SCAN_TYPES))}")
            return 2

    fetch_api_findings = not requested_types or bool(set(requested_types) & API_SCAN_TYPES)
    fetch_iac = not requested_types or "IAC" in requested_types
    include_annotations = not args.no_annotations

    # --- Banner ---
    print("\n" + "=" * 70)
    print("  VERACODE FINDINGS API EXPORT")
    print("=" * 70)
    print(f"  Output File       : {args.output}")
    print(f"  Include Sandboxes : {args.include_sandbox}")
    print(f"  Include Annotations: {include_annotations}")
    print(f"  Scan Types Split  : {not args.combine_scan_types}")
    print(f"  Page Size         : {args.page_size}")
    print(f"  Max Workers       : {args.max_workers}")
    print(f"  Rate Limit        : {args.rate_limit} req/sec "
          f"({args.rate_limit * 60:.0f}/min)")
    print(f"  Retry Attempts    : {DEFAULT_MAX_ATTEMPTS}")
    for label, val in [
        ("CA Cert Bundle", args.ca_cert), ("Filter App Name", args.app_name),
        ("Filter App GUID", args.app_guid), ("Filter Scan Type", args.scan_type),
        ("Filter CWE", args.cwe), ("Filter Status", args.status),
    ]:
        if val:
            print(f"  {label:18s}: {val}")
    if args.severity is not None:
        print(f"  Filter Severity   : {args.severity}")
    if args.severity_gte is not None:
        print(f"  Filter Sev >=     : {args.severity_gte}")
    if not args.include_sandbox:
        print("\n  NOTE: sandbox findings are EXCLUDED. Pass --include-sandbox to")
        print("        include them. This is a common source of platform vs")
        print("        extract discrepancies.")
    print("=" * 70 + "\n")

    # --- Phase 1: Pre-fetch lookup data ---
    sca_map: dict[str, dict[str, str]] = {}
    da_map: dict[str, list[dict[str, Any]]] = {}
    applications: list[dict[str, Any]] = []

    session = create_session(ca_cert=args.ca_cert)
    try:
        if fetch_api_findings:
            print("=" * 70)
            print("  FETCHING SCA WORKSPACE MAPPINGS")
            print("=" * 70)
            sca_map = get_sca_workspaces(session, args.sleep, rate_limiter, tracker)
            print("=" * 70 + "\n")

            print("=" * 70)
            print("  FETCHING DYNAMIC ANALYSIS MAPPINGS")
            print("=" * 70)
            da_map = get_dynamic_analyses(session, args.sleep, rate_limiter, tracker)
            if da_map:
                total_da = sum(len(v) for v in da_map.values())
                print(f"  Found {total_da} Dynamic Analyses across {len(da_map)} applications")
            else:
                print("  No Dynamic Analysis found")
            print("=" * 70 + "\n")

        # --- Phase 2: Resolve application list ---
        if args.app_guid:
            # Fetch the real record. The previous stub had no id/oid/profile,
            # so Team Name came out blank and every static and SCA deep link
            # silently degraded to a generic module-list URL.
            print(f"Processing single application: {args.app_guid}")
            try:
                resp = request_with_retry(
                    session, f"{APPLICATIONS_URL}/{args.app_guid}",
                    scope=f"application[{args.app_guid}]",
                    rate_limiter=rate_limiter, tracker=tracker, timeout=60,
                )
                if resp.status_code == 404:
                    print(f"FATAL: application {args.app_guid} not found.\n")
                    return 1
                applications = [resp.json()]
                nm = (applications[0].get("profile") or {}).get("name", "Unknown")
                print(f"  Resolved: {nm}\n")
            except (FetchError, ValueError) as exc:
                tracker.record_failure(f"application[{args.app_guid}]", str(exc))
                print(f"FATAL: could not resolve application {args.app_guid}: {exc}\n")
                return 1
        else:
            try:
                applications = get_applications(session, rate_limiter, tracker)
            except FetchError as exc:
                tracker.record_failure("applications", str(exc))
                print(f"\nFATAL: could not enumerate applications: {exc}")
                print("Aborting rather than exporting a partial tenant.\n")
                return 1

            if args.app_name:
                target_set = {n.strip() for n in args.app_name.split(",")}
                applications = [
                    a for a in applications
                    if a.get("profile", {}).get("name", "") in target_set
                ]
                print(f"Filtered to {len(applications)} applications matching provided names\n")
                found = {a.get("profile", {}).get("name", "") for a in applications}
                missing = target_set - found
                if missing:
                    print(f"WARNING: Could not find: {', '.join(sorted(missing))}\n")
                    tracker.record_failure(
                        "app-name-filter", f"not found: {', '.join(sorted(missing))}"
                    )
            if args.max_apps:
                applications = applications[:args.max_apps]
                print(f"Limited to {args.max_apps} applications (for testing)\n")
    finally:
        session.close()

    # --- Filter SCA map to relevant apps (link generation only) ---
    if sca_map and applications:
        app_guids = {a.get("guid") for a in applications if a.get("guid")}
        app_names_lc = {a.get("profile", {}).get("name", "").lower() for a in applications}
        app_names_lc.discard("")
        orig = len(sca_map)
        sca_map = {
            k: v for k, v in sca_map.items()
            if (k.startswith("guid:") and k[5:] in app_guids)
            or (not k.startswith("guid:") and k in app_names_lc)
        }
        print(f"  Filtered SCA mappings: {orig} -> {len(sca_map)} (relevant to selected apps)")

    # --- Phase 3: Fetch findings concurrently, streaming to disk ---
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    recon_path = args.output.rsplit(".", 1)[0] + f"_reconciliation_{timestamp}.csv"
    raw_path = (f"veracode_findings_api_raw_{timestamp}.jsonl"
                if args.raw_json else None)

    apps_with_findings = 0
    apps_ok = 0
    apps_failed = 0
    findings_retrieved = 0
    published = False

    exporter = StreamingExporter(
        csv_path=args.output,
        recon_path=recon_path,
        tracker=tracker,
        status_filter=args.status,
        raw_json_path=raw_path,
        dedup=args.dedup,
        excel_bom=args.excel_bom,
    )

    try:
        with exporter:
            if fetch_api_findings:
                print("\n" + "=" * 70)
                print("  FETCHING FINDINGS FROM APPLICATIONS")
                print("=" * 70 + "\n")

                with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
                    def _submit(entry: tuple[int, dict[str, Any]]) -> Any:
                        i, a = entry
                        return executor.submit(
                            _process_application,
                            app=a, idx=i, total=len(applications),
                            filters=filters, sleep_time=args.sleep,
                            include_sandboxes=args.include_sandbox,
                            sca_map=sca_map, da_map=da_map,
                            rate_limiter=rate_limiter, tracker=tracker,
                            page_size=args.page_size,
                            include_annotations=include_annotations,
                            combine_scan_types=args.combine_scan_types,
                            ca_cert=args.ca_cert,
                        )

                    # Bounded sliding window. Submitting all 15,000 tasks up front
                    # and draining with as_completed defeats streaming: completed
                    # futures hold their result lists until consumed, so the whole
                    # tenant ends up resident anyway. Keeping only a few in flight
                    # caps live findings at roughly window x findings-per-app,
                    # while the pool stays saturated.
                    app_iter = iter(list(enumerate(applications, 1)))
                    window = max(2, args.max_workers * 2)
                    pending: deque = deque()
                    for entry in itertools.islice(app_iter, window):
                        pending.append((entry[1], _submit(entry)))

                    while pending:
                        app, future = pending.popleft()
                        name = app.get("profile", {}).get("name", "Unknown")
                        try:
                            findings, rows = future.result()
                            exporter.write_recon(rows)
                            findings_retrieved += len(findings)
                            if findings:
                                apps_with_findings += 1
                            exporter.write_batch(findings)
                            if any(r.get("Status") != "OK" for r in rows):
                                apps_failed += 1
                            else:
                                apps_ok += 1
                            del findings, rows  # release before pulling the next
                        except Exception as exc:
                            apps_failed += 1
                            tracker.record_failure(
                                f"application[{name}]", f"{type(exc).__name__}: {exc}")
                            print(f"    ERROR processing {name}: {exc}\n")

                        nxt = next(app_iter, None)
                        if nxt is not None:
                            pending.append((nxt[1], _submit(nxt)))
            else:
                print("\n  Skipping API findings fetch "
                      "(--scan-type does not include API scan types)\n")

            # --- Phase 4: IaC integration ---
            if fetch_iac:
                print("\n" + "=" * 70)
                print("  FETCHING IAC SCAN DATA")
                print("=" * 70 + "\n")

                iac_filter_set: Optional[set[str]] = None
                if args.app_name:
                    iac_filter_set = {n.strip() for n in args.app_name.split(",") if n.strip()}

                iac_records = _fetch_iac_data_live(
                    rate_limiter=rate_limiter,
                    tracker=tracker,
                    max_workers=args.max_workers,
                    filter_apps=iac_filter_set,
                    ca_cert=args.ca_cert,
                )

                if iac_records:
                    app_by_name: dict[str, dict] = {}
                    app_name_lc: dict[str, str] = {}
                    for app in applications:
                        prof = app.get("profile") or {}
                        nm = prof.get("name", "Unknown")
                        app_by_name[nm] = {"guid": app.get("guid"), "profile": prof}
                        app_name_lc[nm.lower()] = nm

                    iac_count = 0
                    iac_apps = 0
                    unmatched: list[str] = []

                    for rec in iac_records:
                        asset = rec.get("asset_name", "")
                        info = app_by_name.get(asset)
                        if not info:
                            canonical = app_name_lc.get(asset.lower())
                            if canonical:
                                info = app_by_name[canonical]

                        if info:
                            matched_name = info["profile"].get("name", asset)
                        else:
                            sid = rec.get("scan_id", asset)
                            unmatched.append(asset)
                            info = {"guid": str(sid),
                                    "profile": {"name": asset,
                                                "business_unit": {"name": "Unknown"},
                                                "teams": []}}
                            matched_name = asset

                        iac_apps += 1
                        batch = []
                        for iac_finding in rec.get("detailed_findings", []):
                            try:
                                batch.append(normalize_iac_finding(
                                    iac_finding, rec, matched_name,
                                    info["guid"], info["profile"]))
                            except Exception as exc:
                                tracker.record_failure(
                                    f"normalize-iac[{matched_name}]",
                                    f"{type(exc).__name__}: {exc}")
                            iac_count += 1
                        exporter.write_batch(batch)
                        findings_retrieved += len(batch)

                    print(f"\n  Processed {iac_apps} IaC assets")
                    print(f"  Added {iac_count} individual IaC findings")
                    if unmatched:
                        print(f"  {len(unmatched)} IaC asset(s) had no matching "
                              f"application profile and used placeholders")
                else:
                    print("  No IaC scan data found.\n")

        published = True
    except KeyboardInterrupt:
        print("\n\n  INTERRUPTED by user. The destination file was not modified.")
        return 130

    # --- Duplicate analysis ---
    print("\n" + "=" * 70)
    print("  DUPLICATE ANALYSIS")
    print("=" * 70)
    print(f"  Duplicate finding identities "
          f"(app+context+scan_type+issue_id): {exporter.duplicates_seen}")
    for key in exporter.duplicate_samples[:5]:
        print(f"    {key}")
    if exporter.duplicates_removed:
        print(f"  --dedup active: removed {exporter.duplicates_removed} rows")
    elif exporter.duplicates_seen:
        print("  Duplicates retained (pass --dedup to remove them).")
    print("=" * 70)

    # --- Outputs ---
    print("\n" + "=" * 70)
    print("  SAVING RESULTS")
    print("=" * 70)
    print(f"  CSV File      : {args.output} ({exporter.rows_written} findings)")
    print(f"  Reconciliation: {recon_path} ({exporter.recon_written} request contexts)")
    if raw_path:
        print(f"  Raw JSONL     : {raw_path}")
    if args.status:
        print(f"  Client-side status filter '{args.status}' excluded "
              f"{exporter.rows_filtered_out} rows")

    by_scan_type = exporter.by_scan_type

    print("\n" + "=" * 70)
    print("  EXPORT SUMMARY")
    print("=" * 70)
    print(f"  Applications discovered   : {len(applications)}")
    print(f"  Applications COMPLETE     : {apps_ok}")
    print(f"  Applications FAILED       : {apps_failed}")
    print(f"  Applications with findings: {apps_with_findings}")
    print(f"  Work contexts registered  : {exporter.recon_written}")
    print(f"  API pages retrieved       : {tracker.pages_ok}")
    print(f"  API pages failed          : {tracker.pages_failed}")
    print(f"  Findings retrieved        : {findings_retrieved}")
    print(f"  Findings exported         : {exporter.rows_written}")
    delta = findings_retrieved - exporter.rows_written - exporter.rows_filtered_out \
        - exporter.duplicates_removed
    print(f"  Reconciliation delta      : {delta}")
    for st, n in sorted(by_scan_type.items()):
        print(f"    {st:<20}: {n}")
    print(f"  Requests retried          : {tracker.retries} "
          f"({tracker.rate_limit_hits} rate-limit)")
    print(f"  Failed request families   : {len(tracker.failures)}")
    print(f"  Count mismatches          : {len(tracker.mismatches)}")

    if delta != 0:
        tracker.record_mismatch("export-accounting", findings_retrieved,
                                exporter.rows_written)
        print("\n  ! ACCOUNTING DELTA IS NON-ZERO. Rows were lost between "
              "retrieval and export.")

    if tracker.failures:
        print("\n  FAILURES (data is INCOMPLETE for these):")
        for f in tracker.failures[:40]:
            print(f"    - {f['scope']}: {f['detail'][:160]}")
        if len(tracker.failures) > 40:
            print(f"    ... and {len(tracker.failures) - 40} more")

    if tracker.mismatches:
        print("\n  COUNT MISMATCHES (API total vs retrieved):")
        for m in tracker.mismatches[:40]:
            print(f"    - {m['scope']}: {m['detail']}")
        if len(tracker.mismatches) > 40:
            print(f"    ... and {len(tracker.mismatches) - 40} more")

    if tracker.clean:
        print("\n  RESULT: COMPLETE. Every request family succeeded, every")
        print("          API-reported total matched what was retrieved, and")
        print("          every retrieved finding is accounted for in the CSV.")
        status_code = 0
    else:
        print("\n  RESULT: INCOMPLETE. Do not treat this extract as authoritative.")
        print("          Review the reconciliation CSV, then re-run. Consider")
        print("          lowering --rate-limit and --max-workers.")
        status_code = 0 if args.ignore_failures else 1

    print("=" * 70 + "\n")
    return status_code


if __name__ == "__main__":
    sys.exit(main())
