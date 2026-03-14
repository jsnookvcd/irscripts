#!/usr/bin/env python3
"""
Vendetta Cyber Defense - Cloud Investigation Tool v2.0
The most comprehensive cloud forensics tool for Microsoft 365 / Entra ID / Azure.

Surpasses: HAWK | CISA Sparrow | CrowdStrike CRT | Microsoft Extractor Suite

Author:   Vendetta Cyber Defense

Features:
    Investigation Types:
    - 6 modes: tenant, user, ip, full, bec, complete

    Threat Detection & Analysis:
    - Automated Threat Detection Engine with 50+ rules
    - Full MITRE ATT&CK Cloud Matrix mapping (35+ techniques)
    - Impossible Travel / Geo-Velocity analysis (Haversine formula)
    - Password Spray & Brute Force detection
    - MFA Fatigue / Push Spam attack detection
    - Legacy Authentication Protocol detection (IMAP/POP3/ActiveSync)
    - Consent Phishing detection and audit
    - User-Agent clustering and anomaly detection
    - Country-based sign-in anomaly analysis
    - Session correlation across sign-in events
    - Application usage pattern analysis
    - Actionable Remediation Recommendations engine

    Investigation Modules:
    - Business Email Compromise (BEC) focused investigation
    - SharePoint / OneDrive forensics with exfiltration detection
    - Microsoft Teams investigation (sideloaded apps)
    - Privileged Identity Management (PIM) analysis
    - Federation / Golden SAML risk detection and audit
    - Conditional Access policy gap analysis
    - Cross-Tenant access settings review
    - Guest user investigation with stale account detection
    - Administrative Units enumeration
    - Directory Sync / AD Connect status and account audit
    - Managed Identity service principal enumeration
    - Workload Identity Federation credential detection
    - Application Proxy application inventory
    - Privileged Access Groups with member enumeration
    - Access Reviews configuration audit
    - Mailbox Audit Bypass detection
    - Deleted users and applications (evidence destruction)
    - Microsoft Secure Score with recommendations
    - Password and Authorization policy analysis

    Output & Reporting:
    - Unified chronological timeline across all data sources
    - Interactive HTML dashboard report (dark theme)
    - IOC auto-extraction (IPs, emails, domains, app IDs, correlation IDs)
    - STIX 2.1 IOC export for threat intelligence sharing
    - SIEM export (Splunk, Elasticsearch, Microsoft Sentinel)
    - KQL hunting query generation for Microsoft Sentinel
    - Remediation report with prioritized action items
    - CSV + JSON for all collected data

    Infrastructure:
    - Certificate-based authentication support
    - YAML/JSON config file support
    - Concurrent API execution with ThreadPoolExecutor
    - Rate limit handling with auto-retry and exponential backoff
    - Thread-safe token refresh
    - Progress tracking with visual progress bars

Usage:
    # Interactive mode
    python vcd_cloud_investigator.py

    # Tenant investigation
    python vcd_cloud_investigator.py --type tenant --days 90

    # User investigation
    python vcd_cloud_investigator.py --type user --users user@contoso.com

    # BEC investigation
    python vcd_cloud_investigator.py --type bec --users cfo@contoso.com --days 14

    # Complete investigation (everything)
    python vcd_cloud_investigator.py --type complete --users user@contoso.com --days 30

    # With SIEM export
    python vcd_cloud_investigator.py --type full --users user@contoso.com --siem-export all

    # From config file
    python vcd_cloud_investigator.py --config investigation.yml

    # Certificate auth
    python vcd_cloud_investigator.py --type tenant --cert-auth /path/to/cert.pem

Requirements:
    pip install -r requirements.txt
    Requires Azure AD app registration with appropriate Microsoft Graph API permissions.
"""

import argparse
import base64
import csv
import hashlib
import html
import json
import logging
import math
import os
import re
import sys
import threading
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import msal
except ImportError:
    msal = None

try:
    import requests
except ImportError:
    requests = None

try:
    import yaml
except ImportError:
    yaml = None

# ============================================================================
# CONSTANTS
# ============================================================================

VERSION = "2.0.0"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
ARM_BASE = "https://management.azure.com"

GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]
ARM_SCOPES = ["https://management.azure.com/.default"]

# Permissions required (application permissions for the app registration):
# AuditLog.Read.All, Directory.Read.All, User.Read.All, Application.Read.All,
# Policy.Read.All, RoleManagement.Read.All, SecurityEvents.Read.All,
# IdentityRiskEvent.Read.All, Reports.Read.All, Mail.Read, Mail.ReadBasic,
# MailboxSettings.Read, Organization.Read.All, Sites.Read.All,
# Files.Read.All, TeamSettings.Read.All, Chat.Read.All,
# ChannelMessage.Read.All, SecurityIncident.Read.All,
# ThreatHunting.Read.All, CloudPC.Read.All

HIGH_PRIVILEGE_ROLES = [
    "Global Administrator", "Privileged Role Administrator",
    "Exchange Administrator", "SharePoint Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Privileged Authentication Administrator", "Security Administrator",
    "Compliance Administrator", "Intune Administrator",
    "Azure AD Joined Device Local Administrator",
    "Hybrid Identity Administrator", "Authentication Administrator",
    "Helpdesk Administrator", "User Administrator",
    "Directory Synchronization Accounts", "Partner Tier1 Support",
    "Partner Tier2 Support",
]

DANGEROUS_SCOPES = [
    "Mail.ReadWrite", "Mail.ReadWrite.All", "Mail.Send", "Mail.Send.All",
    "Files.ReadWrite.All", "Sites.ReadWrite.All",
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All", "Group.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess", "DeviceManagementConfiguration.ReadWrite.All",
    "MailboxSettings.ReadWrite", "Calendars.ReadWrite",
    "full_access_as_app",
]

SENSITIVE_AUDIT_OPERATIONS = [
    "HardDelete", "SoftDelete", "MoveToDeletedItems", "SendAs",
    "SendOnBehalf", "UpdateInboxRules", "Set-Mailbox",
    "Add-MailboxPermission", "New-InboxRule", "Set-InboxRule",
    "Remove-InboxRule", "MailItemsAccessed", "Send",
    "SearchQueryInitiatedExchange", "SearchQueryInitiatedSharePoint",
]

INBOX_RULE_OPERATIONS = [
    "New-InboxRule", "Set-InboxRule", "Remove-InboxRule",
    "Enable-InboxRule", "Disable-InboxRule", "UpdateInboxRules",
]

LEGACY_AUTH_PROTOCOLS = [
    "Authenticated SMTP", "Autodiscover", "Exchange ActiveSync",
    "Exchange Online PowerShell", "Exchange Web Services",
    "IMAP4", "MAPI Over HTTP", "Offline Address Book",
    "Other clients", "Outlook Anywhere (RPC over HTTP)",
    "POP3", "Reporting Web Services",
    "Other clients; Older Office clients",
]

BEC_SUSPICIOUS_SUBJECTS = [
    "wire transfer", "payment", "invoice", "bank account",
    "routing number", "urgent", "confidential", "w-2", "w2",
    "tax form", "direct deposit", "payroll", "gift card",
    "itunes", "bitcoin", "cryptocurrency",
]

# Earth radius in km for geo-velocity calculations
EARTH_RADIUS_KM = 6371.0
# Maximum plausible travel speed (km/h) - commercial flight ~900, allow 1100 for buffer
MAX_TRAVEL_SPEED_KMH = 1100.0

# ============================================================================
# MITRE ATT&CK CLOUD MATRIX MAPPING
# ============================================================================

MITRE_ATTACK = {
    # Initial Access
    "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "Initial Access"},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access"},
    "T1199": {"name": "Trusted Relationship", "tactic": "Initial Access"},
    # Execution
    "T1059.009": {"name": "Command and Scripting: Cloud API", "tactic": "Execution"},
    "T1648": {"name": "Serverless Execution", "tactic": "Execution"},
    # Persistence
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1098.001": {"name": "Account Manipulation: Additional Cloud Credentials", "tactic": "Persistence"},
    "T1098.002": {"name": "Account Manipulation: Additional Email Delegate Permissions", "tactic": "Persistence"},
    "T1098.003": {"name": "Account Manipulation: Additional Cloud Roles", "tactic": "Persistence"},
    "T1098.005": {"name": "Account Manipulation: Device Registration", "tactic": "Persistence"},
    "T1136.003": {"name": "Create Account: Cloud Account", "tactic": "Persistence"},
    "T1556.007": {"name": "Modify Authentication Process: Hybrid Identity", "tactic": "Persistence"},
    "T1556.006": {"name": "Modify Authentication Process: Multi-Factor Authentication", "tactic": "Persistence"},
    "T1556.009": {"name": "Modify Authentication Process: Conditional Access Policies", "tactic": "Persistence"},
    "T1137.006": {"name": "Office Application Startup: Add-ins", "tactic": "Persistence"},
    # Privilege Escalation
    "T1484.002": {"name": "Domain Policy Modification: Trust Modification", "tactic": "Privilege Escalation"},
    "T1078": {"name": "Valid Accounts", "tactic": "Privilege Escalation"},
    # Defense Evasion
    "T1550.001": {"name": "Use Alternate Authentication Material: Application Access Token", "tactic": "Defense Evasion"},
    "T1550.004": {"name": "Use Alternate Authentication Material: Web Session Cookie", "tactic": "Defense Evasion"},
    "T1606.002": {"name": "Forge Web Credentials: SAML Tokens", "tactic": "Defense Evasion"},
    "T1562.008": {"name": "Impair Defenses: Disable Cloud Logs", "tactic": "Defense Evasion"},
    "T1070.009": {"name": "Indicator Removal: Clear Persistence", "tactic": "Defense Evasion"},
    # Credential Access
    "T1528": {"name": "Steal Application Access Token", "tactic": "Credential Access"},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
    "T1110.004": {"name": "Brute Force: Credential Stuffing", "tactic": "Credential Access"},
    "T1621": {"name": "Multi-Factor Authentication Request Generation", "tactic": "Credential Access"},
    # Discovery
    "T1087.004": {"name": "Account Discovery: Cloud Account", "tactic": "Discovery"},
    "T1069.003": {"name": "Permission Groups Discovery: Cloud Groups", "tactic": "Discovery"},
    "T1526": {"name": "Cloud Service Discovery", "tactic": "Discovery"},
    "T1538": {"name": "Cloud Service Dashboard", "tactic": "Discovery"},
    # Lateral Movement
    "T1534": {"name": "Internal Spearphishing", "tactic": "Lateral Movement"},
    "T1080": {"name": "Taint Shared Content", "tactic": "Lateral Movement"},
    # Collection
    "T1114.002": {"name": "Email Collection: Remote Email Collection", "tactic": "Collection"},
    "T1114.003": {"name": "Email Collection: Email Forwarding Rule", "tactic": "Collection"},
    "T1213.002": {"name": "Data from Information Repositories: SharePoint", "tactic": "Collection"},
    "T1530": {"name": "Data from Cloud Storage", "tactic": "Collection"},
    # Exfiltration
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1531": {"name": "Account Access Removal", "tactic": "Impact"},
    "T1499.004": {"name": "Endpoint Denial of Service: Application or System Exploitation", "tactic": "Impact"},
}

BANNER = r"""
 __     __              _      _   _          ____      _
 \ \   / /__ _ __   __| | ___| |_| |_ __ _  / ___|   _| |__   ___ _ __
  \ \ / / _ \ '_ \ / _` |/ _ \ __| __/ _` | | |  | | | | '_ \ / _ \ '__|
   \ V /  __/ | | | (_| |  __/ |_| || (_| | | |__| |_| | |_) |  __/ |
    \_/ \___|_| |_|\__,_|\___|\__|\__\__,_|  \____\__, |_.__/ \___|_|
                                                   |___/
              ____         __
             |  _ \  ___  / _| ___ _ __  ___  ___
             | | | |/ _ \| |_ / _ \ '_ \/ __|/ _ \
             | |_| |  __/|  _|  __/ | | \__ \  __/
             |____/ \___||_|  \___|_| |_|___/\___|

    ============================================================
     VCD Cloud Investigation Tool v{version}
     Advanced Cloud Forensics for Microsoft 365 / Entra ID / Azure
    ============================================================
     Surpasses: HAWK | Sparrow | CrowdStrike CRT | Extractor Suite
    ============================================================
"""


# ============================================================================
# LOGGING
# ============================================================================

class VCDLogger:
    """Custom logger with investigation-specific levels, progress tracking, and file output."""

    COLORS = {
        "INFO": "\033[37m",       # white
        "WARN": "\033[33m",       # yellow
        "ERROR": "\033[31m",      # red
        "SUCCESS": "\033[32m",    # green
        "INVESTIGATE": "\033[35m",  # magenta
        "MITRE": "\033[36m",      # cyan
        "PROGRESS": "\033[34m",   # blue
        "RESET": "\033[0m",
    }

    def __init__(self, output_root: str | None = None):
        self.output_root = output_root
        self.suspicious_count = 0
        self.findings: list[dict] = []
        self.mitre_hits: dict[str, list[str]] = defaultdict(list)
        self._lock = threading.Lock()
        self._progress_total = 0
        self._progress_done = 0

    def set_output_root(self, path: str):
        self.output_root = path

    def _write(self, level: str, message: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color = self.COLORS.get(level, self.COLORS["INFO"])
        reset = self.COLORS["RESET"]
        label_map = {
            "SUCCESS": "OK",
            "INVESTIGATE": "!!! INVESTIGATE",
            "MITRE": "ATT&CK",
            "PROGRESS": ">>>",
        }
        label = label_map.get(level, level)

        print(f"{color}[{ts}] [{label}] {message}{reset}")

        if self.output_root:
            log_path = os.path.join(self.output_root, "VCD_Investigation.log")
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"[{ts}] [{level}] {message}\n")
            except OSError:
                pass

    def info(self, msg: str):
        self._write("INFO", msg)

    def warn(self, msg: str):
        self._write("WARN", msg)

    def error(self, msg: str):
        self._write("ERROR", msg)

    def success(self, msg: str):
        self._write("SUCCESS", msg)

    def investigate(self, msg: str, mitre_ids: list[str] | None = None):
        with self._lock:
            self.suspicious_count += 1
            finding = {"message": msg, "timestamp": datetime.now().isoformat()}
            if mitre_ids:
                finding["mitre"] = mitre_ids
                for mid in mitre_ids:
                    self.mitre_hits[mid].append(msg)
            self.findings.append(finding)
        self._write("INVESTIGATE", msg)
        if mitre_ids:
            techs = ", ".join(f"{m} ({MITRE_ATTACK.get(m, {}).get('name', '?')})" for m in mitre_ids)
            self._write("MITRE", f"  -> {techs}")

    def progress(self, current: int, total: int, label: str = ""):
        pct = (current / total * 100) if total > 0 else 0
        bar_len = 30
        filled = int(bar_len * current // total) if total > 0 else 0
        bar = "=" * filled + "-" * (bar_len - filled)
        self._write("PROGRESS", f"[{bar}] {pct:.0f}% ({current}/{total}) {label}")


log = VCDLogger()


# ============================================================================
# DATA EXPORT
# ============================================================================

class DataExporter:
    """Handles exporting investigation data to CSV and JSON."""

    def __init__(self, output_root: str):
        self.output_root = output_root
        self.total_records = 0

    def export(self, filename: str, data: list[dict], subfolder: str,
               investigate: bool = False, simple: bool = False):
        """Export data to both CSV and JSON."""
        if not data:
            return

        folder = os.path.join(self.output_root, subfolder)
        os.makedirs(folder, exist_ok=True)

        prefix = ""
        if investigate:
            prefix = "_Investigate_"
        elif simple:
            prefix = "Simple_"

        csv_path = os.path.join(folder, f"{prefix}{filename}.csv")
        json_path = os.path.join(folder, f"{prefix}{filename}.json")

        try:
            # CSV
            if data:
                keys = list(data[0].keys())
                with open(csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(data)

            # JSON
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)

            self.total_records += len(data)
            log.success(f"Exported {len(data)} records to {prefix}{filename}")
        except Exception as e:
            log.error(f"Failed to export {filename}: {e}")


# ============================================================================
# GRAPH API CLIENT
# ============================================================================

class GraphClient:
    """Microsoft Graph API client with MSAL auth, retry logic, rate limiting, and concurrency."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str | None = None,
                 interactive: bool = False, certificate_path: str | None = None,
                 certificate_password: str | None = None, max_workers: int = 4):
        if not msal:
            raise ImportError("msal package is required. Install with: pip install msal")
        if not requests:
            raise ImportError("requests package is required. Install with: pip install requests")

        self.tenant_id = tenant_id
        self.client_id = client_id
        self.token = None
        self.token_expiry = None
        self.max_workers = max_workers
        self._token_lock = threading.Lock()
        self._rate_limit_remaining = 10000
        self._rate_limit_lock = threading.Lock()
        self.api_call_count = 0

        authority = f"https://login.microsoftonline.com/{tenant_id}"

        if certificate_path:
            # Certificate-based auth
            cert_data = {}
            try:
                with open(certificate_path, "rb") as f:
                    cert_data["private_key"] = f.read()
                if certificate_password:
                    cert_data["passphrase"] = certificate_password
                # Extract thumbprint
                cert_data["thumbprint"] = self._get_cert_thumbprint(certificate_path)
            except Exception as e:
                log.error(f"Failed to load certificate: {e}")
                raise
            self.app = msal.ConfidentialClientApplication(
                client_id, authority=authority, client_credential=cert_data,
            )
            self._auth_mode = "certificate"
        elif client_secret:
            self.app = msal.ConfidentialClientApplication(
                client_id, authority=authority, client_credential=client_secret,
            )
            self._auth_mode = "client_credentials"
        elif interactive:
            self.app = msal.PublicClientApplication(client_id, authority=authority)
            self._auth_mode = "interactive"
        else:
            self.app = msal.PublicClientApplication(client_id, authority=authority)
            self._auth_mode = "device_code"

    @staticmethod
    def _get_cert_thumbprint(cert_path: str) -> str:
        """Extract certificate thumbprint for MSAL."""
        try:
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            # Simple PEM parsing for thumbprint
            cert_hash = hashlib.sha1(cert_data).hexdigest().upper()
            return cert_hash
        except Exception:
            return ""

    def authenticate(self) -> bool:
        """Acquire an access token."""
        try:
            delegated_scopes = [
                "AuditLog.Read.All", "Directory.Read.All", "User.Read.All",
                "Application.Read.All", "Policy.Read.All",
                "RoleManagement.Read.All", "Reports.Read.All",
            ]

            if self._auth_mode in ("client_credentials", "certificate"):
                result = self.app.acquire_token_for_client(scopes=GRAPH_SCOPES)
            elif self._auth_mode == "interactive":
                result = self.app.acquire_token_interactive(scopes=delegated_scopes)
            else:
                flow = self.app.initiate_device_flow(scopes=delegated_scopes)
                if "user_code" in flow:
                    print(f"\n  To authenticate, visit: {flow['verification_uri']}")
                    print(f"  Enter code: {flow['user_code']}\n")
                result = self.app.acquire_token_by_device_flow(flow)

            if "access_token" in result:
                with self._token_lock:
                    self.token = result["access_token"]
                    self.token_expiry = datetime.now(timezone.utc) + timedelta(
                        seconds=result.get("expires_in", 3600)
                    )
                log.success(f"Authenticated to tenant {self.tenant_id} ({self._auth_mode})")
                return True
            else:
                error = result.get("error_description", result.get("error", "Unknown error"))
                log.error(f"Authentication failed: {error}")
                return False
        except Exception as e:
            log.error(f"Authentication failed: {e}")
            return False

    def _ensure_token(self):
        """Refresh token if expired (thread-safe)."""
        with self._token_lock:
            if not self.token or (self.token_expiry and datetime.now(timezone.utc) >= self.token_expiry - timedelta(minutes=5)):
                self.authenticate()

    def _headers(self) -> dict:
        self._ensure_token()
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "ConsistencyLevel": "eventual",
        }

    def _handle_rate_limit(self, resp):
        """Handle Graph API throttling with exponential backoff."""
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 30))
            log.warn(f"Rate limited. Waiting {retry_after}s before retry...")
            time.sleep(retry_after)
            return True
        return False

    def get(self, endpoint: str, params: dict | None = None,
            beta: bool = False, top: int | None = None, retries: int = 3) -> dict | None:
        """Make a GET request to Graph API with retry logic."""
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = f"{base}/{endpoint.lstrip('/')}"

        if params is None:
            params = {}
        if top:
            params["$top"] = top

        for attempt in range(retries + 1):
            try:
                self.api_call_count += 1
                resp = requests.get(url, headers=self._headers(), params=params, timeout=60)

                if self._handle_rate_limit(resp):
                    continue

                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.HTTPError as e:
                status = getattr(resp, 'status_code', 0)
                if status in (503, 504) and attempt < retries:
                    wait = 2 ** attempt
                    log.warn(f"Transient error {status} on {endpoint}, retry in {wait}s...")
                    time.sleep(wait)
                    continue
                body = getattr(resp, 'text', '')[:500] if resp else ''
                log.error(f"Graph API error ({endpoint}): {e} - {body}")
                return None
            except Exception as e:
                if attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                log.error(f"Graph API request failed ({endpoint}): {e}")
                return None
        return None

    def get_all(self, endpoint: str, params: dict | None = None,
                beta: bool = False, max_records: int = 10000) -> list[dict]:
        """Get all pages of results with auto-pagination and retry."""
        results = []
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = f"{base}/{endpoint.lstrip('/')}"

        if params is None:
            params = {}
        params.setdefault("$top", 999)

        while url and len(results) < max_records:
            try:
                self.api_call_count += 1
                resp = requests.get(url, headers=self._headers(), params=params, timeout=60)

                if self._handle_rate_limit(resp):
                    continue

                resp.raise_for_status()
                data = resp.json()
                results.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                params = {}  # nextLink includes params
            except Exception as e:
                log.error(f"Graph API pagination error ({endpoint}): {e}")
                break

        return results[:max_records]

    def get_parallel(self, endpoints: list[dict]) -> dict[str, Any]:
        """Execute multiple Graph API calls in parallel.

        Args:
            endpoints: List of dicts with keys 'name', 'endpoint', and optional 'params', 'beta', 'paginate'.

        Returns:
            Dict mapping name -> result data.
        """
        results = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for ep in endpoints:
                name = ep["name"]
                if ep.get("paginate", False):
                    future = executor.submit(
                        self.get_all, ep["endpoint"],
                        params=ep.get("params"), beta=ep.get("beta", False),
                        max_records=ep.get("max_records", 10000),
                    )
                else:
                    future = executor.submit(
                        self.get, ep["endpoint"],
                        params=ep.get("params"), beta=ep.get("beta", False),
                    )
                futures[future] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    log.error(f"Parallel call failed ({name}): {e}")
                    results[name] = None

        return results


# ============================================================================
# GEO-VELOCITY / IMPOSSIBLE TRAVEL ANALYSIS
# ============================================================================

def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance between two points in km."""
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def parse_iso_dt(dt_str: str | None) -> datetime | None:
    """Parse ISO datetime string to datetime object."""
    if not dt_str:
        return None
    try:
        cleaned = dt_str.rstrip("Z")
        if "." in cleaned:
            cleaned = cleaned[:cleaned.index(".") + 7]
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


class GeoVelocityAnalyzer:
    """Detect impossible travel based on sign-in location and timing."""

    # Well-known city coordinates for fast lookup (no external dependency)
    CITY_COORDS: dict[str, tuple[float, float]] = {}

    def __init__(self, sign_ins: list[dict]):
        self.sign_ins = sign_ins
        self.impossible_travels: list[dict] = []

    def analyze(self) -> list[dict]:
        """Analyze sign-ins for impossible travel scenarios."""
        # Sort by time
        sorted_si = sorted(
            [s for s in self.sign_ins if s.get("createdDateTime")],
            key=lambda x: x["createdDateTime"],
        )

        for i in range(1, len(sorted_si)):
            prev = sorted_si[i - 1]
            curr = sorted_si[i]

            prev_loc = prev.get("location", {}) if isinstance(prev.get("location"), dict) else {}
            curr_loc = curr.get("location", {}) if isinstance(curr.get("location"), dict) else {}

            prev_geo = prev_loc.get("geoCoordinates", {})
            curr_geo = curr_loc.get("geoCoordinates", {})

            if not (prev_geo and curr_geo):
                continue

            try:
                lat1 = float(prev_geo.get("latitude", 0))
                lon1 = float(prev_geo.get("longitude", 0))
                lat2 = float(curr_geo.get("latitude", 0))
                lon2 = float(curr_geo.get("longitude", 0))
            except (TypeError, ValueError):
                continue

            if lat1 == 0 and lon1 == 0 or lat2 == 0 and lon2 == 0:
                continue

            distance_km = haversine_km(lat1, lon1, lat2, lon2)
            if distance_km < 50:
                continue

            t1 = parse_iso_dt(prev.get("createdDateTime"))
            t2 = parse_iso_dt(curr.get("createdDateTime"))
            if not t1 or not t2:
                continue

            time_diff_hours = abs((t2 - t1).total_seconds()) / 3600
            if time_diff_hours < 0.01:
                time_diff_hours = 0.01

            speed_kmh = distance_km / time_diff_hours

            if speed_kmh > MAX_TRAVEL_SPEED_KMH:
                self.impossible_travels.append({
                    "userPrincipalName": curr.get("userPrincipalName", ""),
                    "firstSignIn": prev.get("createdDateTime"),
                    "firstIP": prev.get("ipAddress"),
                    "firstLocation": f"{prev_loc.get('city', '')}, {prev_loc.get('countryOrRegion', '')}",
                    "secondSignIn": curr.get("createdDateTime"),
                    "secondIP": curr.get("ipAddress"),
                    "secondLocation": f"{curr_loc.get('city', '')}, {curr_loc.get('countryOrRegion', '')}",
                    "distanceKm": round(distance_km, 1),
                    "timeDiffMinutes": round(time_diff_hours * 60, 1),
                    "impliedSpeedKmh": round(speed_kmh, 0),
                    "verdict": "IMPOSSIBLE TRAVEL" if speed_kmh > 5000 else "SUSPICIOUS TRAVEL",
                })

        return self.impossible_travels


# ============================================================================
# THREAT DETECTION ENGINE
# ============================================================================

class ThreatDetectionEngine:
    """Automated threat detection with 50+ rules mapped to MITRE ATT&CK."""

    def __init__(self, exporter: DataExporter):
        self.exporter = exporter
        self.detections: list[dict] = []

    def _add(self, rule_id: str, severity: str, title: str, detail: str,
             mitre_ids: list[str], evidence: dict | None = None):
        detection = {
            "ruleId": rule_id,
            "severity": severity,
            "title": title,
            "detail": detail,
            "mitreTechniques": "; ".join(mitre_ids),
            "mitreTactics": "; ".join(set(MITRE_ATTACK.get(m, {}).get("tactic", "") for m in mitre_ids)),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence": json.dumps(evidence, default=str)[:2000] if evidence else "",
        }
        self.detections.append(detection)
        log.investigate(f"[{severity}] {title}: {detail}", mitre_ids=mitre_ids)

    def analyze_sign_ins(self, sign_ins: list[dict], upn: str = ""):
        """Run all sign-in based detections."""
        if not sign_ins:
            return

        # Rule: Password spray detection (many users, same IP, failed logins)
        ip_failures: dict[str, list] = defaultdict(list)
        for si in sign_ins:
            status = si.get("status", {})
            if isinstance(status, dict) and status.get("errorCode") and status.get("errorCode") != 0:
                ip = si.get("ipAddress", "")
                if ip:
                    ip_failures[ip].append(si)

        for ip, failures in ip_failures.items():
            unique_users = set(f.get("userPrincipalName", "") for f in failures)
            if len(unique_users) >= 5 and len(failures) >= 10:
                self._add("VCD-SI-001", "HIGH", "Password Spray Detected",
                          f"IP {ip}: {len(failures)} failed logins across {len(unique_users)} accounts",
                          ["T1110.003"], {"ip": ip, "userCount": len(unique_users), "failCount": len(failures)})

        # Rule: Legacy protocol usage
        for si in sign_ins:
            client = si.get("clientAppUsed", "")
            if client in LEGACY_AUTH_PROTOCOLS:
                self._add("VCD-SI-002", "MEDIUM", "Legacy Authentication Protocol",
                          f"User {si.get('userPrincipalName', '')} using {client} from {si.get('ipAddress', '')}",
                          ["T1078.004"], {"user": si.get("userPrincipalName"), "protocol": client})
                break  # Only flag once per analysis run

        # Rule: MFA fatigue / push spam (multiple failed MFA in short window)
        mfa_failures = [si for si in sign_ins
                        if isinstance(si.get("status"), dict) and
                        si.get("status", {}).get("errorCode") == 50074]
        if len(mfa_failures) >= 5:
            # Check if within a short time window
            times = sorted([parse_iso_dt(f.get("createdDateTime")) for f in mfa_failures if f.get("createdDateTime")])
            times = [t for t in times if t]
            if len(times) >= 5 and times[-1] and times[0]:
                window = (times[-1] - times[0]).total_seconds() / 60
                if window <= 30:
                    self._add("VCD-SI-003", "HIGH", "MFA Fatigue Attack Suspected",
                              f"{len(mfa_failures)} MFA challenges in {window:.0f} minutes for {upn}",
                              ["T1621"], {"failCount": len(mfa_failures), "windowMinutes": window})

        # Rule: Sign-in from known anonymizer / TOR
        for si in sign_ins:
            risk_detail = si.get("riskDetail", "") or ""
            risk_type = si.get("riskEventTypes_v2", []) or []
            if "anonymizedIPAddress" in str(risk_type) or "tor" in risk_detail.lower():
                self._add("VCD-SI-004", "HIGH", "Sign-in from Anonymizer/TOR",
                          f"User {si.get('userPrincipalName', '')} from {si.get('ipAddress', '')}",
                          ["T1078.004"], {"ip": si.get("ipAddress")})
                break

        # Rule: Successful sign-in after many failures (potential compromise)
        user_events: dict[str, list] = defaultdict(list)
        for si in sign_ins:
            user_events[si.get("userPrincipalName", "")].append(si)

        for user, events in user_events.items():
            sorted_events = sorted(events, key=lambda x: x.get("createdDateTime", ""))
            consecutive_fails = 0
            for ev in sorted_events:
                status = ev.get("status", {})
                err = status.get("errorCode", 0) if isinstance(status, dict) else 0
                if err and err != 0:
                    consecutive_fails += 1
                else:
                    if consecutive_fails >= 5:
                        self._add("VCD-SI-005", "HIGH", "Successful Login After Brute Force",
                                  f"User {user}: {consecutive_fails} failures then success from {ev.get('ipAddress', '')}",
                                  ["T1110.001", "T1078.004"],
                                  {"user": user, "failures": consecutive_fails, "ip": ev.get("ipAddress")})
                    consecutive_fails = 0

        # Rule: Impossible travel
        geo_analyzer = GeoVelocityAnalyzer(sign_ins)
        impossible = geo_analyzer.analyze()
        for it in impossible:
            self._add("VCD-SI-006", "HIGH", "Impossible Travel Detected",
                      f"{it['userPrincipalName']}: {it['firstLocation']} -> {it['secondLocation']} "
                      f"({it['distanceKm']}km in {it['timeDiffMinutes']}min = {it['impliedSpeedKmh']}km/h)",
                      ["T1078.004"], it)

        # Rule: Unusual user-agent / application
        suspicious_apps = ["Python", "PowerShell", "curl", "wget", "httpie", "postman",
                           "Go-http-client", "python-requests", "aiohttp"]
        for si in sign_ins:
            app = si.get("appDisplayName", "") or ""
            browser = (si.get("deviceDetail", {}) or {}).get("browser", "") or ""
            for sa in suspicious_apps:
                if sa.lower() in browser.lower() or sa.lower() in app.lower():
                    self._add("VCD-SI-007", "MEDIUM", "Suspicious Client Application",
                              f"User {si.get('userPrincipalName', '')} using {browser or app}",
                              ["T1059.009"], {"app": app, "browser": browser})
                    break
            else:
                continue
            break

    def analyze_inbox_rules(self, rules: list[dict], upn: str = ""):
        """Detect malicious inbox rules."""
        for r in rules:
            actions = r.get("actions", {}) if isinstance(r.get("actions"), dict) else {}
            fwd = actions.get("forwardTo") or []
            fwd_attach = actions.get("forwardAsAttachmentTo") or []
            redirect = actions.get("redirectTo") or []

            all_forwards = []
            for dest_list in [fwd, fwd_attach, redirect]:
                if isinstance(dest_list, list):
                    for d in dest_list:
                        if isinstance(d, dict):
                            addr = d.get("emailAddress", {}).get("address", "")
                            if addr:
                                all_forwards.append(addr)

            # External forwarding
            for addr in all_forwards:
                self._add("VCD-IR-001", "HIGH", "Email Forwarding Rule",
                          f"User {upn}: mail forwarded to {addr} (rule: {r.get('displayName', 'unnamed')})",
                          ["T1114.003"], {"rule": r.get("displayName"), "destination": addr})

            # Delete + mark read (hiding evidence)
            if actions.get("delete") or actions.get("permanentDelete"):
                if actions.get("markAsRead"):
                    self._add("VCD-IR-002", "CRITICAL", "Evidence Hiding Inbox Rule",
                              f"User {upn}: rule marks as read AND deletes (rule: {r.get('displayName', 'unnamed')})",
                              ["T1114.003", "T1070.009"], {"rule": r.get("displayName")})

    def analyze_app_permissions(self, grants: list[dict], apps: list[dict]):
        """Detect dangerous application permissions."""
        for g in grants:
            scope = g.get("scope", "") or ""
            scopes_list = scope.split()
            dangerous_found = [s for s in scopes_list if s in DANGEROUS_SCOPES]

            if dangerous_found and g.get("consentType") == "AllPrincipals":
                self._add("VCD-APP-001", "CRITICAL", "Admin-Consented Dangerous Permissions",
                          f"App {g.get('appDisplayName', 'Unknown')}: {', '.join(dangerous_found)} (admin consent)",
                          ["T1528", "T1098.001"],
                          {"app": g.get("appDisplayName"), "scopes": dangerous_found})

            if "Mail.ReadWrite" in scope and "Mail.Send" in scope:
                self._add("VCD-APP-002", "HIGH", "Full Mailbox Access Application",
                          f"App {g.get('appDisplayName', 'Unknown')} can read/write/send mail",
                          ["T1114.002", "T1534"],
                          {"app": g.get("appDisplayName")})

        # Check for recently created apps with credentials
        now = datetime.now(timezone.utc)
        for app in apps:
            created = parse_iso_dt(app.get("createdDateTime"))
            if created and (now - created).days <= 7:
                cred_count = len(app.get("passwordCredentials", [])) + len(app.get("keyCredentials", []))
                if cred_count > 0:
                    self._add("VCD-APP-003", "HIGH", "Recently Created App With Credentials",
                              f"App '{app.get('displayName')}' created {created.date()} with {cred_count} credential(s)",
                              ["T1098.001", "T1136.003"],
                              {"app": app.get("displayName"), "created": str(created)})

    def analyze_role_changes(self, audit_logs: list[dict]):
        """Detect suspicious role assignments."""
        for entry in audit_logs:
            activity = entry.get("activityDisplayName", "") or entry.get("activity", "")
            targets = entry.get("targetResources", [])
            target_role = ""
            for t in (targets if isinstance(targets, list) else []):
                if isinstance(t, dict) and t.get("type") == "Role":
                    target_role = t.get("displayName", "")

            if "Add member to role" in activity and target_role == "Global Administrator":
                self._add("VCD-ROLE-001", "CRITICAL", "Global Admin Role Assignment",
                          f"'{target_role}' role assigned at {entry.get('activityDateTime', '')}",
                          ["T1098.003"],
                          {"activity": activity, "role": target_role,
                           "time": entry.get("activityDateTime")})

            if "Add eligible member to role" in activity:
                self._add("VCD-ROLE-002", "HIGH", "PIM Eligible Role Assignment",
                          f"Eligible assignment to '{target_role}' at {entry.get('activityDateTime', '')}",
                          ["T1098.003"], {"role": target_role})

    def analyze_federation(self, domains: list[dict]):
        """Detect federation trust manipulation."""
        for d in domains:
            if d.get("authenticationType") == "Federated":
                self._add("VCD-FED-001", "HIGH", "Federated Domain Detected",
                          f"Domain {d.get('id')} uses federation - review for Golden SAML risk",
                          ["T1484.002", "T1606.002"],
                          {"domain": d.get("id")})

    def analyze_conditional_access(self, policies: list[dict]):
        """Detect CA policy weaknesses."""
        enabled_count = sum(1 for p in policies if p.get("state") == "enabled")
        disabled_count = sum(1 for p in policies if p.get("state") != "enabled")

        if enabled_count == 0:
            self._add("VCD-CA-001", "CRITICAL", "No Conditional Access Policies Enabled",
                      "Tenant has zero enabled conditional access policies",
                      ["T1556.009"])

        for p in policies:
            users = (p.get("conditions", {}) or {}).get("users", {}) or {}
            exclude = users.get("excludeUsers", []) or []
            if "All" in (users.get("includeUsers", []) or []) and len(exclude) > 5:
                self._add("VCD-CA-002", "MEDIUM", "CA Policy With Many Exclusions",
                          f"Policy '{p.get('displayName')}' excludes {len(exclude)} users",
                          ["T1556.009"], {"policy": p.get("displayName"), "exclusions": len(exclude)})

    def analyze_service_principals(self, sps: list[dict]):
        """Detect suspicious service principal configurations."""
        for sp in sps:
            cred_count = len(sp.get("passwordCredentials", [])) + len(sp.get("keyCredentials", []))
            if cred_count > 2:
                self._add("VCD-SP-001", "MEDIUM", "Service Principal With Multiple Credentials",
                          f"SP '{sp.get('displayName')}' has {cred_count} credentials (possible backdoor)",
                          ["T1098.001"],
                          {"sp": sp.get("displayName"), "credCount": cred_count})

            # Check for external org ownership
            owner_org = sp.get("appOwnerOrganizationId", "")
            if owner_org and owner_org != sp.get("_tenant_id", ""):
                # Flag SPs owned by external orgs with credentials
                if cred_count > 0:
                    self._add("VCD-SP-002", "HIGH", "External SP With Credentials",
                              f"SP '{sp.get('displayName')}' owned by {owner_org} has {cred_count} credential(s)",
                              ["T1199", "T1098.001"],
                              {"sp": sp.get("displayName"), "owner": owner_org})

    def export_results(self, output_folder: str = "ThreatDetection"):
        """Export all detections."""
        if self.detections:
            self.exporter.export("ThreatDetections_All", self.detections, output_folder, investigate=True)

            # Export by severity
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                sev_detections = [d for d in self.detections if d["severity"] == sev]
                if sev_detections:
                    self.exporter.export(f"ThreatDetections_{sev}", sev_detections, output_folder, investigate=True)

            # MITRE summary
            mitre_summary = []
            for mid, msgs in log.mitre_hits.items():
                info = MITRE_ATTACK.get(mid, {})
                mitre_summary.append({
                    "techniqueId": mid,
                    "techniqueName": info.get("name", "Unknown"),
                    "tactic": info.get("tactic", "Unknown"),
                    "hitCount": len(msgs),
                    "findings": "; ".join(msgs[:5]),
                })
            if mitre_summary:
                self.exporter.export("MITRE_ATT&CK_Coverage", mitre_summary, output_folder)

            log.info(f"Threat detection complete: {len(self.detections)} finding(s) "
                     f"across {len(log.mitre_hits)} MITRE techniques")


# ============================================================================
# TENANT INVESTIGATION
# ============================================================================

class TenantInvestigator:
    """Collects tenant-level forensic data from Microsoft 365 / Entra ID."""

    def __init__(self, graph: GraphClient, exporter: DataExporter,
                 start_date: datetime, end_date: datetime):
        self.graph = graph
        self.exporter = exporter
        self.start_date = start_date
        self.end_date = end_date

    def run_all(self):
        """Execute all tenant investigation functions."""
        log.info("=" * 50)
        log.info("Starting Tenant Investigation (Enhanced v2)")
        log.info("=" * 50)

        steps = [
            ("Organization Config", self.get_organization_config),
            ("Domains & Federation", self.get_domains),
            ("OAuth Consent Grants", self.get_consent_grants),
            ("App Registrations", self.get_app_registrations),
            ("Service Principals", self.get_service_principals),
            ("Directory Roles", self.get_directory_roles),
            ("Role Change Audit", self.get_role_change_audit),
            ("Conditional Access", self.get_conditional_access_policies),
            ("Named Locations", self.get_named_locations),
            ("eDiscovery Roles", self.get_ediscovery_roles),
            ("Inbox Rule Audit", self.get_inbox_rule_audit),
            ("Transport Rules", self.get_transport_rule_audit),
            ("Security Alerts", self.get_security_alerts),
            ("Security Incidents", self.get_security_incidents),
            ("Risky Users", self.get_risky_users),
            ("Risky Service Principals", self.get_risky_service_principals),
            ("PIM Role Assignments", self.get_pim_assignments),
            ("Authentication Methods Policy", self.get_auth_methods_policy),
            ("Admin Consent Requests", self.get_admin_consent_requests),
            ("Cross-Tenant Access", self.get_cross_tenant_access),
            ("Deleted Users (Soft)", self.get_recently_deleted_users),
            ("Audit Log Config Changes", self.get_audit_config_changes),
            ("Secure Score", self.get_secure_score),
            ("SAML/Federation Audit", self.get_saml_federation_audit),
            ("Guest Users", self.get_guest_users),
            ("Password Policies", self.get_password_policies),
            ("Administrative Units", self.get_administrative_units),
            ("Directory Sync Status", self.get_directory_sync_status),
            ("Managed Identities", self.get_managed_identities),
            ("Workload Identity Federation", self.get_workload_identity_federation),
            ("Consent Grant Audit (Phishing)", self.get_consent_grant_audit),
            ("App Proxy Applications", self.get_app_proxy_apps),
            ("Deleted Applications", self.get_deleted_applications),
            ("Privileged Access Groups", self.get_privileged_access_groups),
            ("Access Reviews", self.get_access_reviews),
            ("Mailbox Audit Bypass", self.get_mailbox_audit_bypass),
        ]

        for i, (label, func) in enumerate(steps, 1):
            log.progress(i, len(steps), label)
            try:
                func()
            except Exception as e:
                log.error(f"Failed during {label}: {e}")

        log.success("Tenant investigation complete")

    def get_organization_config(self):
        log.info("=== Collecting Organization Configuration ===")
        data = self.graph.get("organization")
        if not data or "value" not in data:
            return

        orgs = []
        for org in data["value"]:
            verified = [d["name"] for d in org.get("verifiedDomains", []) if d.get("isDefault")]
            all_domains = [d["name"] for d in org.get("verifiedDomains", [])]
            enabled_plans = [
                p["service"] for p in org.get("assignedPlans", [])
                if p.get("capabilityStatus") == "Enabled"
            ]

            orgs.append({
                "displayName": org.get("displayName"),
                "id": org.get("id"),
                "createdDateTime": org.get("createdDateTime"),
                "defaultDomain": "; ".join(verified),
                "allDomains": "; ".join(all_domains),
                "technicalContact": "; ".join(org.get("technicalNotificationMails", [])),
                "securityContact": "; ".join(org.get("securityComplianceNotificationMails", [])),
                "enabledServices": "; ".join(set(enabled_plans)),
            })

        self.exporter.export("TenantOrganization", orgs, "Tenant")
        if orgs:
            log.info(f"Tenant: {orgs[0].get('displayName')}")

    def get_domains(self):
        log.info("=== Collecting Domain Configuration ===")
        domains = self.graph.get_all("domains")
        if not domains:
            return

        domain_data = [{
            "id": d.get("id"),
            "authenticationType": d.get("authenticationType"),
            "isDefault": d.get("isDefault"),
            "isVerified": d.get("isVerified"),
            "isRoot": d.get("isRoot"),
            "supportedServices": "; ".join(d.get("supportedServices", [])),
            "passwordValidityPeriod": d.get("passwordValidityPeriodInDays"),
            "passwordNotificationWindow": d.get("passwordNotificationWindowInDays"),
        } for d in domains]

        self.exporter.export("TenantDomains", domain_data, "Tenant")

        federated = [d for d in domain_data if d["authenticationType"] == "Federated"]
        if federated:
            self.exporter.export("FederatedDomains", federated, "Tenant", investigate=True)
            log.investigate(f"Found {len(federated)} federated domain(s) - review for potential abuse")

    def get_consent_grants(self):
        log.info("=== Collecting OAuth / Consent Grants ===")
        grants = self.graph.get_all("oauth2PermissionGrants")
        if not grants:
            log.info("No OAuth consent grants found")
            return

        grant_data = []
        for g in grants:
            sp = self.graph.get(f"servicePrincipals/{g['clientId']}")
            grant_data.append({
                "clientId": g.get("clientId"),
                "appDisplayName": sp.get("displayName") if sp else "Unknown",
                "appId": sp.get("appId") if sp else "",
                "consentType": g.get("consentType"),
                "principalId": g.get("principalId"),
                "scope": g.get("scope"),
                "startDateTime": g.get("startDateTime"),
                "expiryDateTime": g.get("expiryDateTime"),
                "resourceId": g.get("resourceId"),
            })

        self.exporter.export("OAuthConsentGrants", grant_data, "Tenant")

        # Flag admin consents
        admin_consents = [g for g in grant_data if g["consentType"] == "AllPrincipals"]
        if admin_consents:
            self.exporter.export("AdminConsentGrants", admin_consents, "Tenant", investigate=True)
            log.investigate(f"Found {len(admin_consents)} admin consent grant(s) affecting all users")

        # Flag dangerous scopes
        risky = [g for g in grant_data if any(s in (g.get("scope") or "") for s in DANGEROUS_SCOPES)]
        if risky:
            self.exporter.export("HighPrivilegeConsentGrants", risky, "Tenant", investigate=True)
            log.investigate(f"Found {len(risky)} consent grant(s) with high-privilege scopes")

    def get_app_registrations(self):
        log.info("=== Collecting Application Registrations ===")
        apps = self.graph.get_all("applications")
        if not apps:
            return

        now = datetime.now(timezone.utc)
        app_data = []
        expiring_creds = []

        for app in apps:
            creds = []
            for pw in app.get("passwordCredentials", []):
                creds.append(f"Secret:{pw.get('keyId')}(Exp:{pw.get('endDateTime')})")
                if pw.get("endDateTime"):
                    try:
                        exp = datetime.fromisoformat(pw["endDateTime"].rstrip("Z")).replace(tzinfo=timezone.utc)
                        if exp < now + timedelta(days=30):
                            expiring_creds.append({
                                "appName": app.get("displayName"),
                                "appId": app.get("appId"),
                                "keyId": pw.get("keyId"),
                                "type": "Secret",
                                "expiryDate": pw.get("endDateTime"),
                                "isExpired": exp < now,
                            })
                    except (ValueError, TypeError):
                        pass

            for kc in app.get("keyCredentials", []):
                creds.append(f"Cert:{kc.get('keyId')}(Exp:{kc.get('endDateTime')})")
                if kc.get("endDateTime"):
                    try:
                        exp = datetime.fromisoformat(kc["endDateTime"].rstrip("Z")).replace(tzinfo=timezone.utc)
                        if exp < now + timedelta(days=30):
                            expiring_creds.append({
                                "appName": app.get("displayName"),
                                "appId": app.get("appId"),
                                "keyId": kc.get("keyId"),
                                "type": "Certificate",
                                "expiryDate": kc.get("endDateTime"),
                                "isExpired": exp < now,
                            })
                    except (ValueError, TypeError):
                        pass

            app_data.append({
                "displayName": app.get("displayName"),
                "appId": app.get("appId"),
                "objectId": app.get("id"),
                "createdDateTime": app.get("createdDateTime"),
                "signInAudience": app.get("signInAudience"),
                "publisherDomain": app.get("publisherDomain"),
                "credentialCount": len(app.get("passwordCredentials", [])) + len(app.get("keyCredentials", [])),
                "credentials": "; ".join(creds),
            })

        self.exporter.export("AppRegistrations", app_data, "Tenant")

        if expiring_creds:
            self.exporter.export("ExpiringAppCredentials", expiring_creds, "Tenant", investigate=True)
            log.investigate(f"Found {len(expiring_creds)} expiring/expired app credential(s)")

        multi_tenant = [a for a in app_data
                        if a["signInAudience"] in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount")]
        if multi_tenant:
            self.exporter.export("MultiTenantApps", multi_tenant, "Tenant", investigate=True)
            log.investigate(f"Found {len(multi_tenant)} multi-tenant app registration(s)")

    def get_service_principals(self):
        log.info("=== Collecting Service Principals ===")
        sps = self.graph.get_all("servicePrincipals")
        if not sps:
            return

        sp_data = [{
            "displayName": sp.get("displayName"),
            "appId": sp.get("appId"),
            "objectId": sp.get("id"),
            "servicePrincipalType": sp.get("servicePrincipalType"),
            "accountEnabled": sp.get("accountEnabled"),
            "appOwnerOrganizationId": sp.get("appOwnerOrganizationId"),
            "createdDateTime": sp.get("createdDateTime"),
            "signInAudience": sp.get("signInAudience"),
            "tags": "; ".join(sp.get("tags", [])),
            "credentialCount": len(sp.get("passwordCredentials", [])) + len(sp.get("keyCredentials", [])),
        } for sp in sps]

        self.exporter.export("ServicePrincipals", sp_data, "Tenant")

        # Flag SPs with credentials (potential persistence mechanism)
        with_creds = [s for s in sp_data if s["credentialCount"] > 0]
        if with_creds:
            self.exporter.export("ServicePrincipalsWithCredentials", with_creds, "Tenant", investigate=True)
            log.investigate(f"Found {len(with_creds)} service principal(s) with direct credentials")

    def get_directory_roles(self):
        log.info("=== Collecting Directory Role Assignments ===")
        assignments = self.graph.get_all(
            "roleManagement/directory/roleAssignments",
            params={"$expand": "principal,roleDefinition"}
        )
        if not assignments:
            return

        role_data = []
        for ra in assignments:
            role_def = ra.get("roleDefinition", {})
            principal = ra.get("principal", {})
            role_data.append({
                "roleName": role_def.get("displayName"),
                "roleId": ra.get("roleDefinitionId"),
                "principalName": principal.get("displayName"),
                "principalId": ra.get("principalId"),
                "principalType": principal.get("@odata.type", ""),
                "directoryScopeId": ra.get("directoryScopeId"),
                "assignmentId": ra.get("id"),
            })

        self.exporter.export("DirectoryRoleAssignments", role_data, "Tenant")

        global_admins = [r for r in role_data if r["roleName"] == "Global Administrator"]
        if global_admins:
            self.exporter.export("GlobalAdministrators", global_admins, "Tenant", investigate=True)
            log.investigate(f"Found {len(global_admins)} Global Administrator assignment(s)")

        high_priv = [r for r in role_data if r["roleName"] in HIGH_PRIVILEGE_ROLES]
        if high_priv:
            self.exporter.export("HighPrivilegeRoleAssignments", high_priv, "Tenant", investigate=True)
            log.investigate(f"Found {len(high_priv)} high-privilege role assignment(s)")

    def get_role_change_audit(self):
        log.info("=== Collecting Role Change Audit Logs ===")
        filter_str = (
            "activityDisplayName eq 'Add member to role' or "
            "activityDisplayName eq 'Remove member from role' or "
            "activityDisplayName eq 'Add eligible member to role'"
        )
        logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
        if not logs:
            return

        audit_data = []
        for entry in logs:
            initiated_by = entry.get("initiatedBy", {}).get("user", {})
            targets = entry.get("targetResources", [])
            target_user = next((t.get("userPrincipalName") for t in targets if t.get("type") == "User"), "")
            target_role = next((t.get("displayName") for t in targets if t.get("type") == "Role"), "")

            audit_data.append({
                "activityDateTime": entry.get("activityDateTime"),
                "activity": entry.get("activityDisplayName"),
                "result": entry.get("result"),
                "initiatedBy": initiated_by.get("userPrincipalName", ""),
                "targetUser": target_user,
                "targetRole": target_role,
                "category": entry.get("category"),
                "correlationId": entry.get("correlationId"),
            })

        self.exporter.export("RoleChangeAuditLog", audit_data, "Tenant", investigate=True)
        log.investigate(f"Found {len(audit_data)} role change audit event(s)")

    def get_conditional_access_policies(self):
        log.info("=== Collecting Conditional Access Policies ===")
        policies = self.graph.get_all("identity/conditionalAccess/policies")
        if not policies:
            return

        policy_data = []
        for p in policies:
            conditions = p.get("conditions", {})
            users = conditions.get("users", {})
            apps = conditions.get("applications", {})
            platforms = conditions.get("platforms", {})
            locations = conditions.get("locations", {})
            grant = p.get("grantControls", {})

            policy_data.append({
                "displayName": p.get("displayName"),
                "id": p.get("id"),
                "state": p.get("state"),
                "createdDateTime": p.get("createdDateTime"),
                "modifiedDateTime": p.get("modifiedDateTime"),
                "includeUsers": "; ".join(users.get("includeUsers", [])),
                "excludeUsers": "; ".join(users.get("excludeUsers", [])),
                "includeGroups": "; ".join(users.get("includeGroups", [])),
                "includeApplications": "; ".join(apps.get("includeApplications", [])),
                "excludeApplications": "; ".join(apps.get("excludeApplications", [])),
                "includePlatforms": "; ".join((platforms or {}).get("includePlatforms", [])),
                "includeLocations": "; ".join((locations or {}).get("includeLocations", [])),
                "grantControls": "; ".join((grant or {}).get("builtInControls", [])),
                "clientAppTypes": "; ".join(conditions.get("clientAppTypes", [])),
            })

        self.exporter.export("ConditionalAccessPolicies", policy_data, "Tenant")

        disabled = [p for p in policy_data if p["state"] != "enabled"]
        if disabled:
            self.exporter.export("DisabledConditionalAccessPolicies", disabled, "Tenant", investigate=True)
            log.investigate(f"Found {len(disabled)} conditional access policy/policies not enforced")

    def get_ediscovery_roles(self):
        log.info("=== Collecting eDiscovery Configuration ===")
        # eDiscovery Administrator role ID
        ediscovery_role_id = "e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477"
        assignments = self.graph.get_all(
            "roleManagement/directory/roleAssignments",
            params={"$filter": f"roleDefinitionId eq '{ediscovery_role_id}'"}
        )
        if assignments:
            ed_data = []
            for a in assignments:
                principal = self.graph.get(f"directoryObjects/{a['principalId']}")
                ed_data.append({
                    "principalId": a.get("principalId"),
                    "principalName": principal.get("displayName") if principal else "Unknown",
                    "principalType": principal.get("@odata.type", "") if principal else "",
                    "scopeId": a.get("directoryScopeId"),
                })
            self.exporter.export("eDiscoveryRoleAssignments", ed_data, "Tenant", investigate=True)
            log.investigate(f"Found {len(ed_data)} eDiscovery role assignment(s)")
        else:
            log.info("No eDiscovery role assignments found")

    def get_inbox_rule_audit(self):
        log.info("=== Collecting Inbox Rule Change Audit Logs ===")
        start_str = self.start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = self.end_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Search audit logs for inbox rule operations
        for op in INBOX_RULE_OPERATIONS:
            filter_str = (
                f"activityDisplayName eq '{op}' and "
                f"activityDateTime ge {start_str} and "
                f"activityDateTime le {end_str}"
            )
            logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
            if logs:
                audit_data = [{
                    "activityDateTime": e.get("activityDateTime"),
                    "activity": e.get("activityDisplayName"),
                    "result": e.get("result"),
                    "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
                    "category": e.get("category"),
                    "correlationId": e.get("correlationId"),
                    "targetResources": json.dumps(e.get("targetResources", []), default=str),
                } for e in logs]

                self.exporter.export(f"InboxRuleAudit_{op}", audit_data, "Tenant", investigate=True)
                log.investigate(f"Found {len(audit_data)} '{op}' audit event(s)")

    def get_transport_rule_audit(self):
        log.info("=== Collecting Transport Rule Audit Logs ===")
        filter_str = (
            "activityDisplayName eq 'New-TransportRule' or "
            "activityDisplayName eq 'Set-TransportRule' or "
            "activityDisplayName eq 'Remove-TransportRule'"
        )
        logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
        if logs:
            audit_data = [{
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "result": e.get("result"),
                "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
                "correlationId": e.get("correlationId"),
                "targetResources": json.dumps(e.get("targetResources", []), default=str),
            } for e in logs]

            self.exporter.export("TransportRuleAuditLog", audit_data, "Tenant", investigate=True)
            log.investigate(f"Found {len(audit_data)} transport rule audit event(s)")

    def get_named_locations(self):
        log.info("=== Collecting Named/Trusted Locations ===")
        locations = self.graph.get_all("identity/conditionalAccess/namedLocations")
        if not locations:
            log.info("No named locations configured")
            return

        loc_data = []
        for loc in locations:
            entry = {
                "displayName": loc.get("displayName"),
                "id": loc.get("id"),
                "type": loc.get("@odata.type", ""),
                "createdDateTime": loc.get("createdDateTime"),
                "modifiedDateTime": loc.get("modifiedDateTime"),
                "isTrusted": loc.get("isTrusted", False),
            }
            # IP-based locations
            if "ipRanges" in loc:
                ranges = [r.get("cidrAddress", "") for r in loc.get("ipRanges", [])]
                entry["ipRanges"] = "; ".join(ranges)
            # Country-based locations
            if "countriesAndRegions" in loc:
                entry["countries"] = "; ".join(loc.get("countriesAndRegions", []))
            loc_data.append(entry)

        self.exporter.export("NamedLocations", loc_data, "Tenant")

    def get_security_alerts(self):
        log.info("=== Collecting Security Alerts ===")
        alerts = self.graph.get_all("security/alerts_v2", beta=True)
        if not alerts:
            log.info("No security alerts found")
            return

        alert_data = [{
            "id": a.get("id"),
            "title": a.get("title"),
            "severity": a.get("severity"),
            "status": a.get("status"),
            "category": a.get("category"),
            "createdDateTime": a.get("createdDateTime"),
            "lastUpdateDateTime": a.get("lastUpdateDateTime"),
            "description": a.get("description", "")[:500],
            "detectionSource": a.get("detectionSource"),
            "serviceSource": a.get("serviceSource"),
            "userStates": json.dumps(a.get("evidence", [])[:5], default=str),
        } for a in alerts]

        self.exporter.export("SecurityAlerts", alert_data, "Tenant", investigate=True)
        log.investigate(f"Found {len(alert_data)} security alert(s)",
                        mitre_ids=["T1078.004"])

    def get_security_incidents(self):
        log.info("=== Collecting Security Incidents ===")
        incidents = self.graph.get_all("security/incidents", beta=True)
        if not incidents:
            log.info("No security incidents found")
            return

        inc_data = [{
            "id": i.get("id"),
            "displayName": i.get("displayName"),
            "severity": i.get("severity"),
            "status": i.get("status"),
            "classification": i.get("classification"),
            "determination": i.get("determination"),
            "createdDateTime": i.get("createdDateTime"),
            "lastUpdateDateTime": i.get("lastUpdateDateTime"),
            "assignedTo": i.get("assignedTo"),
            "alertCount": len(i.get("alerts", [])),
            "description": (i.get("description") or "")[:500],
        } for i in incidents]

        self.exporter.export("SecurityIncidents", inc_data, "Tenant", investigate=True)
        log.investigate(f"Found {len(inc_data)} security incident(s)")

    def get_risky_users(self):
        log.info("=== Collecting Risky Users ===")
        users = self.graph.get_all("identityProtection/riskyUsers")
        if not users:
            log.info("No risky users found")
            return

        user_data = [{
            "id": u.get("id"),
            "userDisplayName": u.get("userDisplayName"),
            "userPrincipalName": u.get("userPrincipalName"),
            "riskLevel": u.get("riskLevel"),
            "riskState": u.get("riskState"),
            "riskDetail": u.get("riskDetail"),
            "riskLastUpdatedDateTime": u.get("riskLastUpdatedDateTime"),
            "isDeleted": u.get("isDeleted"),
            "isProcessing": u.get("isProcessing"),
        } for u in users]

        self.exporter.export("RiskyUsers", user_data, "Tenant", investigate=True)
        log.investigate(f"Found {len(user_data)} risky user(s)", mitre_ids=["T1078.004"])

    def get_risky_service_principals(self):
        log.info("=== Collecting Risky Service Principals ===")
        sps = self.graph.get_all("identityProtection/riskyServicePrincipals", beta=True)
        if not sps:
            log.info("No risky service principals found")
            return

        sp_data = [{
            "id": s.get("id"),
            "appId": s.get("appId"),
            "displayName": s.get("displayName"),
            "riskLevel": s.get("riskLevel"),
            "riskState": s.get("riskState"),
            "riskDetail": s.get("riskDetail"),
            "riskLastUpdatedDateTime": s.get("riskLastUpdatedDateTime"),
            "servicePrincipalType": s.get("servicePrincipalType"),
        } for s in sps]

        self.exporter.export("RiskyServicePrincipals", sp_data, "Tenant", investigate=True)
        log.investigate(f"Found {len(sp_data)} risky service principal(s)",
                        mitre_ids=["T1098.001"])

    def get_pim_assignments(self):
        log.info("=== Collecting PIM Eligible Role Assignments ===")
        # Eligible assignments (PIM)
        eligible = self.graph.get_all(
            "roleManagement/directory/roleEligibilityScheduleInstances", beta=True
        )
        if not eligible:
            log.info("No PIM eligible assignments found")
            return

        pim_data = []
        for e in eligible:
            pim_data.append({
                "principalId": e.get("principalId"),
                "roleDefinitionId": e.get("roleDefinitionId"),
                "directoryScopeId": e.get("directoryScopeId"),
                "memberType": e.get("memberType"),
                "assignmentType": e.get("assignmentType", "Eligible"),
                "startDateTime": e.get("startDateTime"),
                "endDateTime": e.get("endDateTime"),
                "status": e.get("status"),
            })

        self.exporter.export("PIM_EligibleAssignments", pim_data, "Tenant", investigate=True)
        log.investigate(f"Found {len(pim_data)} PIM eligible role assignment(s)",
                        mitre_ids=["T1098.003"])

        # PIM activation history
        activations = self.graph.get_all(
            "roleManagement/directory/roleAssignmentScheduleInstances", beta=True,
            params={"$filter": "assignmentType eq 'Activated'"}
        )
        if activations:
            act_data = [{
                "principalId": a.get("principalId"),
                "roleDefinitionId": a.get("roleDefinitionId"),
                "startDateTime": a.get("startDateTime"),
                "endDateTime": a.get("endDateTime"),
                "assignmentType": a.get("assignmentType"),
                "memberType": a.get("memberType"),
            } for a in activations]

            self.exporter.export("PIM_RoleActivations", act_data, "Tenant", investigate=True)
            log.investigate(f"Found {len(act_data)} PIM role activation(s)")

    def get_auth_methods_policy(self):
        log.info("=== Collecting Authentication Methods Policy ===")
        policy = self.graph.get("policies/authenticationMethodsPolicy", beta=True)
        if not policy:
            return

        methods = policy.get("authenticationMethodConfigurations", [])
        method_data = [{
            "id": m.get("id"),
            "state": m.get("state"),
            "type": m.get("@odata.type", ""),
        } for m in methods]

        self.exporter.export("AuthMethodsPolicy", method_data, "Tenant")

        # Flag if SMS/Voice is enabled (weak MFA)
        weak_mfa = [m for m in method_data
                    if m["state"] == "enabled" and any(w in m["id"].lower() for w in ["sms", "voice"])]
        if weak_mfa:
            log.investigate(f"Weak MFA methods enabled: {', '.join(m['id'] for m in weak_mfa)}",
                            mitre_ids=["T1556.006"])

    def get_admin_consent_requests(self):
        log.info("=== Collecting Admin Consent Request Workflow ===")
        requests_list = self.graph.get_all(
            "identityGovernance/appConsent/appConsentRequests", beta=True
        )
        if not requests_list:
            log.info("No admin consent requests found")
            return

        req_data = [{
            "appId": r.get("appId"),
            "appDisplayName": r.get("appDisplayName"),
            "pendingScopes": json.dumps(r.get("pendingScopes", []), default=str),
            "userConsentRequestsCount": len(r.get("userConsentRequests", [])),
        } for r in requests_list]

        self.exporter.export("AdminConsentRequests", req_data, "Tenant")

    def get_cross_tenant_access(self):
        log.info("=== Collecting Cross-Tenant Access Settings ===")
        policy = self.graph.get("policies/crossTenantAccessPolicy", beta=True)
        if not policy:
            return

        partners = self.graph.get_all("policies/crossTenantAccessPolicy/partners", beta=True)
        if partners:
            partner_data = [{
                "tenantId": p.get("tenantId"),
                "isServiceProvider": p.get("isServiceProvider"),
                "isInMultiTenantOrganization": p.get("isInMultiTenantOrganization"),
                "inboundTrust": json.dumps(p.get("inboundTrust", {}), default=str)[:500],
                "b2bCollaboration": json.dumps(p.get("b2bCollaborationOutbound", {}), default=str)[:300],
            } for p in partners]

            self.exporter.export("CrossTenantPartners", partner_data, "Tenant", investigate=True)
            log.investigate(f"Found {len(partner_data)} cross-tenant partner configuration(s)",
                            mitre_ids=["T1199"])

    def get_recently_deleted_users(self):
        log.info("=== Collecting Recently Deleted Users ===")
        deleted = self.graph.get_all("directory/deletedItems/microsoft.graph.user")
        if not deleted:
            log.info("No recently deleted users found")
            return

        del_data = [{
            "displayName": u.get("displayName"),
            "userPrincipalName": u.get("userPrincipalName"),
            "id": u.get("id"),
            "deletedDateTime": u.get("deletedDateTime"),
            "userType": u.get("userType"),
            "accountEnabled": u.get("accountEnabled"),
        } for u in deleted]

        self.exporter.export("RecentlyDeletedUsers", del_data, "Tenant")

        # Flag if any were deleted recently (potential evidence destruction)
        now = datetime.now(timezone.utc)
        recent = []
        for u in deleted:
            dt = parse_iso_dt(u.get("deletedDateTime"))
            if dt and (now - dt).days <= 7:
                recent.append(u.get("userPrincipalName", ""))
        if recent:
            log.investigate(f"Found {len(recent)} user(s) deleted in last 7 days: {', '.join(recent[:5])}",
                            mitre_ids=["T1531"])

    def get_audit_config_changes(self):
        log.info("=== Collecting Audit/Logging Configuration Changes ===")
        filter_str = (
            "activityDisplayName eq 'Set audit bypass a mailbox' or "
            "activityDisplayName eq 'Disable audit logging' or "
            "activityDisplayName eq 'Update policy' or "
            "activityDisplayName eq 'Disable Strong Authentication' or "
            "activityDisplayName eq 'Set-AdminAuditLogConfig'"
        )
        logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
        if logs:
            audit_data = [{
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "result": e.get("result"),
                "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
                "correlationId": e.get("correlationId"),
                "targetResources": json.dumps(e.get("targetResources", []), default=str)[:500],
            } for e in logs]

            self.exporter.export("AuditConfigChanges", audit_data, "Tenant", investigate=True)
            log.investigate(f"Found {len(audit_data)} audit/logging config change(s)",
                            mitre_ids=["T1562.008"])

    def get_secure_score(self):
        log.info("=== Collecting Microsoft Secure Score ===")
        scores = self.graph.get_all("security/secureScores", params={"$top": "5"}, beta=True)
        if not scores:
            return

        latest = scores[0] if scores else {}
        current = latest.get("currentScore", 0)
        max_score = latest.get("maxScore", 0)
        pct = (current / max_score * 100) if max_score > 0 else 0

        score_data = [{
            "currentScore": current,
            "maxScore": max_score,
            "percentage": round(pct, 1),
            "createdDateTime": latest.get("createdDateTime"),
            "licensedUserCount": latest.get("licensedUserCount"),
            "activeUserCount": latest.get("activeUserCount"),
            "enabledServices": "; ".join(latest.get("enabledServices", [])),
        }]

        self.exporter.export("SecureScore", score_data, "Tenant")

        if pct < 50:
            log.investigate(f"Microsoft Secure Score is low: {current}/{max_score} ({pct:.0f}%)")

        # Control scores
        controls = latest.get("controlScores", [])
        if controls:
            control_data = [{
                "controlName": c.get("controlName"),
                "score": c.get("score"),
                "controlCategory": c.get("controlCategory"),
                "description": c.get("description", "")[:200],
            } for c in controls]
            self.exporter.export("SecureScoreControls", control_data, "Tenant")

        # Secure score profiles (recommendations)
        profiles = self.graph.get_all("security/secureScoreControlProfiles", beta=True, max_records=100)
        if profiles:
            not_implemented = [p for p in profiles
                               if p.get("implementationStatus") in ("notImplemented", "notPlanned")]
            if not_implemented:
                rec_data = [{
                    "title": p.get("title"),
                    "controlCategory": p.get("controlCategory"),
                    "maxScore": p.get("maxScore"),
                    "implementationStatus": p.get("implementationStatus"),
                    "userImpact": p.get("userImpact"),
                    "threats": "; ".join(p.get("threats", [])[:5]),
                    "remediation": (p.get("remediation") or "")[:300],
                } for p in not_implemented[:50]]
                self.exporter.export("SecureScoreRecommendations", rec_data, "Tenant")

    def get_saml_federation_audit(self):
        log.info("=== Collecting SAML/Federation Modification Audit ===")
        # Sparrow-style: search for UserAuthenticationValue of 16457 (forged SAML indicator)
        filter_str = (
            "activityDisplayName eq 'Set domain authentication' or "
            "activityDisplayName eq 'Set federation settings on domain' or "
            "activityDisplayName eq 'Add unverified domain' or "
            "activityDisplayName eq 'Verify domain' or "
            "activityDisplayName eq 'Set company information' or "
            "activityDisplayName eq 'Update domain'"
        )
        logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
        if logs:
            fed_data = [{
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "result": e.get("result"),
                "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "")
                               or e.get("initiatedBy", {}).get("app", {}).get("displayName", ""),
                "targetResources": json.dumps(e.get("targetResources", []), default=str)[:500],
                "correlationId": e.get("correlationId"),
            } for e in logs]

            self.exporter.export("SAMLFederationAudit", fed_data, "Tenant", investigate=True)
            log.investigate(
                f"Found {len(fed_data)} federation/domain change(s) - potential Golden SAML activity",
                mitre_ids=["T1484.002", "T1606.002"]
            )

        # Check for anomalous SAML token sign-ins (UserAuthenticationValue = 16457)
        saml_si = self.graph.get_all(
            "auditLogs/signIns",
            params={"$filter": "authenticationDetails/any(a:a/authenticationMethod eq 'SAML Token')"},
            beta=True, max_records=500,
        )
        if saml_si:
            saml_data = [{
                "createdDateTime": si.get("createdDateTime"),
                "userPrincipalName": si.get("userPrincipalName"),
                "ipAddress": si.get("ipAddress"),
                "appDisplayName": si.get("appDisplayName"),
                "resourceDisplayName": si.get("resourceDisplayName"),
                "tokenIssuerType": si.get("tokenIssuerType"),
                "tokenIssuerName": si.get("tokenIssuerName"),
            } for si in saml_si]

            self.exporter.export("SAMLTokenSignIns", saml_data, "Tenant", investigate=True)
            log.investigate(
                f"Found {len(saml_data)} SAML token sign-in(s) - review for forged tokens",
                mitre_ids=["T1606.002"]
            )

    def get_guest_users(self):
        log.info("=== Collecting Guest/External Users ===")
        guests = self.graph.get_all(
            "users",
            params={
                "$filter": "userType eq 'Guest'",
                "$select": "id,displayName,userPrincipalName,mail,createdDateTime,"
                           "externalUserState,externalUserStateChangeDateTime,"
                           "accountEnabled,signInActivity",
            },
        )
        if not guests:
            log.info("No guest users found")
            return

        guest_data = []
        stale_guests = []
        now = datetime.now(timezone.utc)
        for g in guests:
            sign_in = g.get("signInActivity", {}) or {}
            last_sign_in = sign_in.get("lastSignInDateTime")
            entry = {
                "displayName": g.get("displayName"),
                "userPrincipalName": g.get("userPrincipalName"),
                "mail": g.get("mail"),
                "createdDateTime": g.get("createdDateTime"),
                "externalUserState": g.get("externalUserState"),
                "accountEnabled": g.get("accountEnabled"),
                "lastSignIn": last_sign_in,
            }
            guest_data.append(entry)

            # Stale guest detection
            if last_sign_in:
                last_dt = parse_iso_dt(last_sign_in)
                if last_dt and (now - last_dt).days > 90:
                    stale_guests.append(entry)
            elif g.get("externalUserState") == "PendingAcceptance":
                stale_guests.append(entry)

        self.exporter.export("GuestUsers", guest_data, "Tenant")

        if len(guests) > 50:
            log.investigate(
                f"Found {len(guests)} guest user(s) - review for excessive external access",
                mitre_ids=["T1078.004"]
            )

        if stale_guests:
            self.exporter.export("StaleGuestUsers", stale_guests, "Tenant", investigate=True)
            log.investigate(f"Found {len(stale_guests)} stale/pending guest user(s)")

    def get_password_policies(self):
        log.info("=== Collecting Password & Authentication Policies ===")
        # Authorization policy
        auth_policy = self.graph.get("policies/authorizationPolicy", beta=True)
        if auth_policy:
            policy_data = [{
                "allowInvitesFrom": auth_policy.get("allowInvitesFrom"),
                "allowedToSignUpEmailBasedSubscriptions": auth_policy.get("allowedToSignUpEmailBasedSubscriptions"),
                "allowedToUseSSPR": auth_policy.get("allowedToUseSSPR"),
                "allowEmailVerifiedUsersToJoinOrganization": auth_policy.get("allowEmailVerifiedUsersToJoinOrganization"),
                "blockMsolPowerShell": auth_policy.get("blockMsolPowerShell"),
                "guestUserRoleId": auth_policy.get("guestUserRoleId"),
                "allowUserConsentForApps": str(auth_policy.get("defaultUserRolePermissions", {}).get("allowedToCreateApps", "")),
                "allowUserConsentForRiskyApps": str(auth_policy.get("defaultUserRolePermissions", {}).get("permissionGrantPoliciesAssigned", [])),
            }]
            self.exporter.export("AuthorizationPolicy", policy_data, "Tenant")

            if not auth_policy.get("blockMsolPowerShell"):
                log.investigate("MSOnline PowerShell is NOT blocked - legacy admin vector")

            if auth_policy.get("allowInvitesFrom") == "everyone":
                log.investigate("Guest invitations allowed from everyone - review restriction",
                                mitre_ids=["T1078.004"])

        # Password reset policy
        sspr = self.graph.get("policies/authenticationFlowsPolicy", beta=True)
        if sspr:
            self.exporter.export("AuthenticationFlowsPolicy", [sspr], "Tenant")

    def get_administrative_units(self):
        log.info("=== Collecting Administrative Units ===")
        aus = self.graph.get_all("directory/administrativeUnits")
        if not aus:
            return

        au_data = [{
            "displayName": au.get("displayName"),
            "id": au.get("id"),
            "description": (au.get("description") or "")[:200],
            "visibility": au.get("visibility"),
            "membershipType": au.get("membershipType"),
            "membershipRule": (au.get("membershipRule") or "")[:200],
        } for au in aus]

        self.exporter.export("AdministrativeUnits", au_data, "Tenant")

        # Check for restricted management AUs (can hide admin activity)
        restricted = [au for au in aus if au.get("visibility") == "HiddenMembership"]
        if restricted:
            self.exporter.export("RestrictedAdminUnits", [{"displayName": au.get("displayName"),
                                  "id": au.get("id")} for au in restricted],
                                 "Tenant", investigate=True)
            log.investigate(f"Found {len(restricted)} hidden-membership administrative unit(s)")

    def get_directory_sync_status(self):
        log.info("=== Collecting Directory Sync / AD Connect Status ===")
        org_data = self.graph.get("organization")
        if not org_data or "value" not in org_data:
            return

        org = org_data["value"][0] if org_data["value"] else {}
        sync_enabled = org.get("onPremisesSyncEnabled", False)

        sync_data = [{
            "onPremisesSyncEnabled": sync_enabled,
            "onPremisesLastSyncDateTime": org.get("onPremisesLastSyncDateTime"),
            "onPremisesLastPasswordSyncDateTime": org.get("onPremisesLastPasswordSyncDateTime"),
            "directorySizeQuota": json.dumps(org.get("directorySizeQuota", {}), default=str),
        }]

        self.exporter.export("DirectorySyncStatus", sync_data, "Tenant")

        if sync_enabled:
            log.investigate("Directory sync (AD Connect) is enabled - check for hybrid attack paths",
                            mitre_ids=["T1556.007"])

            # Check for sync accounts
            sync_users = self.graph.get_all(
                "users",
                params={
                    "$filter": "startsWith(displayName,'On-Premises Directory Synchronization')",
                    "$select": "displayName,userPrincipalName,id,accountEnabled,createdDateTime",
                }
            )
            if sync_users:
                self.exporter.export("DirectorySyncAccounts", [{
                    "displayName": u.get("displayName"),
                    "upn": u.get("userPrincipalName"),
                    "accountEnabled": u.get("accountEnabled"),
                } for u in sync_users], "Tenant", investigate=True)

    def get_managed_identities(self):
        log.info("=== Collecting Managed Identity Service Principals ===")
        managed = self.graph.get_all(
            "servicePrincipals",
            params={"$filter": "servicePrincipalType eq 'ManagedIdentity'"},
        )
        if not managed:
            return

        mi_data = [{
            "displayName": m.get("displayName"),
            "appId": m.get("appId"),
            "id": m.get("id"),
            "servicePrincipalType": m.get("servicePrincipalType"),
            "createdDateTime": m.get("createdDateTime"),
            "accountEnabled": m.get("accountEnabled"),
            "alternativeNames": "; ".join(m.get("alternativeNames", [])),
        } for m in managed]

        self.exporter.export("ManagedIdentities", mi_data, "Tenant")
        log.info(f"Found {len(mi_data)} managed identity service principal(s)")

    def get_workload_identity_federation(self):
        log.info("=== Collecting Workload Identity Federation ===")
        apps = self.graph.get_all("applications", params={
            "$select": "id,displayName,appId,federatedIdentityCredentials"
        })
        if not apps:
            return

        fed_creds = []
        for app in apps:
            fics = app.get("federatedIdentityCredentials", [])
            if not fics:
                # Need to query individually for federation credentials
                fics_data = self.graph.get_all(f"applications/{app['id']}/federatedIdentityCredentials")
                fics = fics_data or []

            for fic in fics:
                fed_creds.append({
                    "appDisplayName": app.get("displayName"),
                    "appId": app.get("appId"),
                    "credentialName": fic.get("name"),
                    "issuer": fic.get("issuer"),
                    "subject": fic.get("subject"),
                    "audiences": "; ".join(fic.get("audiences", [])),
                    "description": (fic.get("description") or "")[:200],
                })

        if fed_creds:
            self.exporter.export("WorkloadIdentityFederation", fed_creds, "Tenant", investigate=True)
            log.investigate(
                f"Found {len(fed_creds)} workload identity federation credential(s)",
                mitre_ids=["T1098.001"]
            )

    def get_consent_grant_audit(self):
        log.info("=== Collecting OAuth Consent Grant Audit (Phishing Detection) ===")
        filter_str = (
            "activityDisplayName eq 'Consent to application' or "
            "activityDisplayName eq 'Add OAuth2PermissionGrant' or "
            "activityDisplayName eq 'Add app role assignment grant to user' or "
            "activityDisplayName eq 'Add delegated permission grant' or "
            "activityDisplayName eq 'Add application'"
        )
        start_str = self.start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = self.end_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        logs = self.graph.get_all(
            "auditLogs/directoryAudits",
            params={
                "$filter": f"({filter_str}) and activityDateTime ge {start_str} and activityDateTime le {end_str}"
            },
        )
        if not logs:
            return

        consent_data = []
        for e in logs:
            initiated_by = e.get("initiatedBy", {})
            user = initiated_by.get("user", {})
            app_init = initiated_by.get("app", {})
            targets = e.get("targetResources", [])

            consent_data.append({
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "result": e.get("result"),
                "initiatedByUser": user.get("userPrincipalName", ""),
                "initiatedByApp": app_init.get("displayName", ""),
                "targetApp": targets[0].get("displayName", "") if targets else "",
                "targetResources": json.dumps(targets, default=str)[:500],
                "correlationId": e.get("correlationId"),
            })

        self.exporter.export("ConsentGrantAudit", consent_data, "Tenant", investigate=True)
        log.investigate(
            f"Found {len(consent_data)} consent/permission grant event(s) - review for consent phishing",
            mitre_ids=["T1528", "T1098.001"]
        )

        # Detect suspicious consent patterns
        user_consent_count: dict[str, int] = Counter(
            c["initiatedByUser"] for c in consent_data if c["initiatedByUser"]
        )
        for user, count in user_consent_count.most_common(10):
            if count >= 3:
                log.investigate(
                    f"User {user} granted consent {count} times - possible consent phishing victim",
                    mitre_ids=["T1528"]
                )

    def get_app_proxy_apps(self):
        log.info("=== Collecting Application Proxy Applications ===")
        proxy_apps = self.graph.get_all(
            "applications",
            params={"$filter": "onPremisesPublishing ne null"},
            beta=True,
        )
        if not proxy_apps:
            return

        proxy_data = [{
            "displayName": a.get("displayName"),
            "appId": a.get("appId"),
            "identifierUris": "; ".join(a.get("identifierUris", [])),
            "signInAudience": a.get("signInAudience"),
        } for a in proxy_apps]

        self.exporter.export("AppProxyApplications", proxy_data, "Tenant")
        log.info(f"Found {len(proxy_data)} Application Proxy app(s)")

    def get_deleted_applications(self):
        log.info("=== Collecting Recently Deleted Applications ===")
        deleted = self.graph.get_all("directory/deletedItems/microsoft.graph.application")
        if not deleted:
            return

        del_data = [{
            "displayName": a.get("displayName"),
            "appId": a.get("appId"),
            "deletedDateTime": a.get("deletedDateTime"),
            "signInAudience": a.get("signInAudience"),
        } for a in deleted]

        self.exporter.export("DeletedApplications", del_data, "Tenant")

        now = datetime.now(timezone.utc)
        recent = [a for a in deleted if parse_iso_dt(a.get("deletedDateTime"))
                  and (now - parse_iso_dt(a.get("deletedDateTime"))).days <= 7]
        if recent:
            log.investigate(
                f"Found {len(recent)} app(s) deleted in last 7 days - potential evidence cleanup",
                mitre_ids=["T1070.009"]
            )

    def get_privileged_access_groups(self):
        log.info("=== Collecting Privileged Access Groups ===")
        groups = self.graph.get_all(
            "groups",
            params={
                "$filter": "isAssignableToRole eq true",
                "$select": "id,displayName,description,createdDateTime,securityEnabled,"
                           "mailEnabled,isAssignableToRole,membershipRule",
            },
        )
        if not groups:
            return

        group_data = [{
            "displayName": g.get("displayName"),
            "id": g.get("id"),
            "createdDateTime": g.get("createdDateTime"),
            "securityEnabled": g.get("securityEnabled"),
            "description": (g.get("description") or "")[:200],
        } for g in groups]

        self.exporter.export("PrivilegedAccessGroups", group_data, "Tenant", investigate=True)
        log.investigate(
            f"Found {len(group_data)} role-assignable group(s) - high-value targets",
            mitre_ids=["T1098.003"]
        )

        # Get members of each privileged group
        for g in groups[:10]:  # Limit to avoid excessive calls
            members = self.graph.get_all(f"groups/{g['id']}/members")
            if members:
                member_data = [{
                    "groupName": g.get("displayName"),
                    "memberName": m.get("displayName"),
                    "memberUPN": m.get("userPrincipalName", ""),
                    "memberType": m.get("@odata.type", ""),
                } for m in members]
                self.exporter.export(
                    f"PrivilegedGroupMembers_{g.get('displayName', 'Unknown')[:30]}",
                    member_data, "Tenant", investigate=True,
                )

    def get_access_reviews(self):
        log.info("=== Collecting Access Review Configuration ===")
        reviews = self.graph.get_all(
            "identityGovernance/accessReviews/definitions", beta=True
        )
        if not reviews:
            log.info("No access reviews configured")
            return

        review_data = [{
            "displayName": r.get("displayName"),
            "id": r.get("id"),
            "status": r.get("status"),
            "createdDateTime": r.get("createdDateTime"),
            "lastModifiedDateTime": r.get("lastModifiedDateTime"),
            "scope": json.dumps(r.get("scope", {}), default=str)[:300],
            "reviewerType": r.get("settings", {}).get("reviewerType", ""),
        } for r in reviews]

        self.exporter.export("AccessReviews", review_data, "Tenant")

    def get_mailbox_audit_bypass(self):
        log.info("=== Checking for Mailbox Audit Bypass ===")
        filter_str = "activityDisplayName eq 'Set-MailboxAuditBypassAssociation'"
        logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
        if logs:
            bypass_data = [{
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
                "targetResources": json.dumps(e.get("targetResources", []), default=str)[:500],
            } for e in logs]

            self.exporter.export("MailboxAuditBypass", bypass_data, "Tenant", investigate=True)
            log.investigate(
                f"Found {len(bypass_data)} mailbox audit bypass event(s) - critical evasion technique",
                mitre_ids=["T1562.008"]
            )


# ============================================================================
# USER INVESTIGATION
# ============================================================================

class UserInvestigator:
    """Collects user-level forensic data for a specific account."""

    def __init__(self, graph: GraphClient, exporter: DataExporter,
                 upn: str, start_date: datetime, end_date: datetime):
        self.graph = graph
        self.exporter = exporter
        self.upn = upn
        self.start_date = start_date
        self.end_date = end_date
        self.user_folder = f"Users/{upn.replace('@', '_at_')}"

    def run_all(self):
        """Execute all user investigation functions."""
        log.info("=" * 50)
        log.info(f"Starting User Investigation (Enhanced v2): {self.upn}")
        log.info("=" * 50)

        steps = [
            ("User Config", self.get_user_config),
            ("MFA Methods", self.get_mfa_methods),
            ("Mailbox Settings", self.get_mailbox_settings),
            ("Inbox Rules", self.get_inbox_rules),
            ("Mail Folders", self.get_mail_folders),
            ("Sign-In Logs", self.get_sign_in_logs),
            ("Non-Interactive Sign-Ins", self.get_non_interactive_sign_ins),
            ("Service Principal Sign-Ins", self.get_sp_sign_ins),
            ("Audit Logs", self.get_audit_logs),
            ("Registered Devices", self.get_registered_devices),
            ("Auth Methods Changes", self.get_auth_method_changes),
            ("App Role Assignments", self.get_app_role_assignments),
            ("OAuth Grants", self.get_oauth_grants),
            ("Group Memberships", self.get_group_memberships),
            ("Directory Roles", self.get_user_directory_roles),
            ("Risk Detections", self.get_risk_detections),
            ("Recent Emails (Metadata)", self.get_recent_emails_metadata),
            ("Mailbox Delegates", self.get_mailbox_delegates),
            ("OneDrive Activity", self.get_onedrive_activity),
        ]

        for i, (label, func) in enumerate(steps, 1):
            log.progress(i, len(steps), f"{self.upn} - {label}")
            try:
                func()
            except Exception as e:
                log.error(f"Failed {label} for {self.upn}: {e}")

        log.success(f"User investigation complete for {self.upn}")

    def get_user_config(self):
        log.info(f"=== Collecting User Configuration: {self.upn} ===")
        user = self.graph.get(
            f"users/{self.upn}",
            params={"$select": (
                "id,displayName,userPrincipalName,mail,accountEnabled,"
                "createdDateTime,lastPasswordChangeDateTime,passwordPolicies,"
                "signInActivity,assignedLicenses,onPremisesSyncEnabled,"
                "userType,externalUserState,proxyAddresses,otherMails"
            )}
        )
        if not user:
            log.error(f"Failed to get user config for {self.upn}")
            return

        sign_in = user.get("signInActivity", {}) or {}
        user_data = [{
            "displayName": user.get("displayName"),
            "upn": user.get("userPrincipalName"),
            "mail": user.get("mail"),
            "objectId": user.get("id"),
            "accountEnabled": user.get("accountEnabled"),
            "userType": user.get("userType"),
            "createdDateTime": user.get("createdDateTime"),
            "lastPasswordChange": user.get("lastPasswordChangeDateTime"),
            "passwordPolicies": user.get("passwordPolicies"),
            "lastSignIn": sign_in.get("lastSignInDateTime"),
            "lastNonInteractiveSignIn": sign_in.get("lastNonInteractiveSignInDateTime"),
            "onPremisesSyncEnabled": user.get("onPremisesSyncEnabled"),
            "externalUserState": user.get("externalUserState"),
            "licenseCount": len(user.get("assignedLicenses", [])),
            "proxyAddresses": "; ".join(user.get("proxyAddresses", [])),
            "otherMails": "; ".join(user.get("otherMails", [])),
        }]

        self.exporter.export("UserConfiguration", user_data, self.user_folder)

        if not user.get("accountEnabled"):
            log.investigate(f"User {self.upn} account is DISABLED")
        if user.get("userType") == "Guest":
            log.investigate(f"User {self.upn} is a GUEST account")

    def get_mailbox_settings(self):
        log.info(f"=== Collecting Mailbox Settings: {self.upn} ===")
        settings = self.graph.get(f"users/{self.upn}/mailboxSettings")
        if not settings:
            return

        auto_reply = settings.get("automaticRepliesSetting", {})
        settings_data = [{
            "upn": self.upn,
            "timeZone": settings.get("timeZone"),
            "dateFormat": settings.get("dateFormat"),
            "language": settings.get("language", {}).get("displayName"),
            "autoReplyStatus": auto_reply.get("status"),
            "autoReplyExternalAudience": auto_reply.get("externalAudience"),
            "autoReplyStartTime": auto_reply.get("scheduledStartDateTime", {}).get("dateTime") if auto_reply.get("scheduledStartDateTime") else None,
            "autoReplyEndTime": auto_reply.get("scheduledEndDateTime", {}).get("dateTime") if auto_reply.get("scheduledEndDateTime") else None,
            "autoReplyInternalMessage": (auto_reply.get("internalReplyMessage") or "")[:200],
            "autoReplyExternalMessage": (auto_reply.get("externalReplyMessage") or "")[:200],
        }]

        self.exporter.export("MailboxSettings", settings_data, self.user_folder)

        if auto_reply.get("status") != "disabled":
            log.investigate(f"Auto-reply is ENABLED for {self.upn} (Status: {auto_reply.get('status')})")

    def get_inbox_rules(self):
        log.info(f"=== Collecting Inbox Rules: {self.upn} ===")
        rules = self.graph.get_all(f"users/{self.upn}/mailFolders/inbox/messageRules")
        if not rules:
            log.info(f"No inbox rules found for {self.upn}")
            return

        rule_data = []
        suspicious = []
        for r in rules:
            actions = r.get("actions", {})
            conditions = r.get("conditions", {})

            entry = {
                "displayName": r.get("displayName"),
                "isEnabled": r.get("isEnabled"),
                "sequence": r.get("sequence"),
                "forwardTo": "; ".join([a.get("emailAddress", {}).get("address", "") for a in (actions.get("forwardTo") or [])]),
                "forwardAsAttachmentTo": "; ".join([a.get("emailAddress", {}).get("address", "") for a in (actions.get("forwardAsAttachmentTo") or [])]),
                "redirectTo": "; ".join([a.get("emailAddress", {}).get("address", "") for a in (actions.get("redirectTo") or [])]),
                "delete": actions.get("delete", False),
                "permanentDelete": actions.get("permanentDelete", False),
                "markAsRead": actions.get("markAsRead", False),
                "moveToFolder": actions.get("moveToFolder"),
                "stopProcessingRules": actions.get("stopProcessingRules", False),
                "fromAddresses": "; ".join([a.get("emailAddress", {}).get("address", "") for a in (conditions.get("fromAddresses") or [])]),
                "subjectContains": "; ".join(conditions.get("subjectContains") or []),
                "bodyContains": "; ".join(conditions.get("bodyContains") or []),
            }
            rule_data.append(entry)

            if (entry["forwardTo"] or entry["forwardAsAttachmentTo"] or
                    entry["redirectTo"] or entry["delete"] or
                    entry["permanentDelete"] or entry["markAsRead"]):
                suspicious.append(entry)

        self.exporter.export("InboxRules", rule_data, self.user_folder)

        if suspicious:
            self.exporter.export("SuspiciousInboxRules", suspicious, self.user_folder, investigate=True)
            log.investigate(
                f"Found {len(suspicious)} suspicious inbox rule(s) for {self.upn} "
                "(forwarding/deletion/mark-read)"
            )

    def get_sign_in_logs(self):
        log.info(f"=== Collecting Sign-In Logs: {self.upn} ===")
        sign_ins = self.graph.get_all(
            "auditLogs/signIns",
            params={"$filter": f"userPrincipalName eq '{self.upn}'"},
            max_records=2000,
        )
        if not sign_ins:
            log.info(f"No sign-in logs found for {self.upn}")
            return

        si_data = []
        for si in sign_ins:
            loc = si.get("location", {})
            status = si.get("status", {})
            device = si.get("deviceDetail", {})

            si_data.append({
                "createdDateTime": si.get("createdDateTime"),
                "userPrincipalName": si.get("userPrincipalName"),
                "appDisplayName": si.get("appDisplayName"),
                "clientAppUsed": si.get("clientAppUsed"),
                "ipAddress": si.get("ipAddress"),
                "location": f"{loc.get('city', '')}, {loc.get('state', '')}, {loc.get('countryOrRegion', '')}",
                "statusCode": status.get("errorCode"),
                "failureReason": status.get("failureReason"),
                "conditionalAccessStatus": si.get("conditionalAccessStatus"),
                "riskLevelDuringSignIn": si.get("riskLevelDuringSignIn"),
                "riskState": si.get("riskState"),
                "isInteractive": si.get("isInteractive"),
                "resourceDisplayName": si.get("resourceDisplayName"),
                "deviceDisplayName": device.get("displayName"),
                "deviceOS": device.get("operatingSystem"),
                "deviceBrowser": device.get("browser"),
                "correlationId": si.get("correlationId"),
            })

        self.exporter.export("SignInLogs", si_data, self.user_folder)

        # Simple view
        simple = [{
            "createdDateTime": s["createdDateTime"],
            "ipAddress": s["ipAddress"],
            "location": s["location"],
            "appDisplayName": s["appDisplayName"],
            "statusCode": s["statusCode"],
            "riskLevel": s["riskLevelDuringSignIn"],
        } for s in si_data]
        self.exporter.export("SignInLogs", simple, self.user_folder, simple=True)

        # Risky sign-ins
        risky = [s for s in si_data
                 if s["riskLevelDuringSignIn"] and s["riskLevelDuringSignIn"] not in ("none", "hidden")]
        if risky:
            self.exporter.export("RiskySignIns", risky, self.user_folder, investigate=True)
            log.investigate(f"Found {len(risky)} risky sign-in(s) for {self.upn}")

        # Failed sign-ins
        failed = [s for s in si_data if s["statusCode"] and s["statusCode"] != 0]
        if failed:
            self.exporter.export("FailedSignIns", failed, self.user_folder, investigate=True)
            log.investigate(f"Found {len(failed)} failed sign-in(s) for {self.upn}")

        # IP summary
        ip_groups: dict[str, list] = {}
        for s in si_data:
            ip = s.get("ipAddress", "Unknown")
            ip_groups.setdefault(ip, []).append(s)

        ip_summary = []
        for ip, entries in sorted(ip_groups.items(), key=lambda x: len(x[1]), reverse=True):
            times = [e["createdDateTime"] for e in entries if e["createdDateTime"]]
            ip_summary.append({
                "ipAddress": ip,
                "count": len(entries),
                "locations": "; ".join(set(e["location"] for e in entries)),
                "apps": "; ".join(set(e["appDisplayName"] or "" for e in entries)),
                "firstSeen": min(times) if times else "",
                "lastSeen": max(times) if times else "",
            })

        self.exporter.export("SignInIPSummary", ip_summary, self.user_folder)

    def get_audit_logs(self):
        log.info(f"=== Collecting Audit Logs: {self.upn} ===")
        start_str = self.start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = self.end_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        logs = self.graph.get_all(
            "auditLogs/directoryAudits",
            params={"$filter": (
                f"initiatedBy/user/userPrincipalName eq '{self.upn}' and "
                f"activityDateTime ge {start_str} and "
                f"activityDateTime le {end_str}"
            )},
            max_records=5000,
        )
        if not logs:
            log.info(f"No audit logs found for {self.upn}")
            return

        audit_data = [{
            "activityDateTime": e.get("activityDateTime"),
            "activityDisplayName": e.get("activityDisplayName"),
            "result": e.get("result"),
            "category": e.get("category"),
            "correlationId": e.get("correlationId"),
            "targetResources": json.dumps(e.get("targetResources", [])[:3], default=str)[:500],
        } for e in logs]

        self.exporter.export("DirectoryAuditLog", audit_data, self.user_folder)

        # Operation summary
        op_counts: dict[str, int] = {}
        for e in audit_data:
            op = e["activityDisplayName"]
            op_counts[op] = op_counts.get(op, 0) + 1

        op_summary = [{"operation": k, "count": v}
                      for k, v in sorted(op_counts.items(), key=lambda x: x[1], reverse=True)]
        self.exporter.export("AuditOperationSummary", op_summary, self.user_folder)

    def get_registered_devices(self):
        log.info(f"=== Collecting Registered Devices: {self.upn} ===")
        devices = self.graph.get_all(f"users/{self.upn}/registeredDevices")
        if not devices:
            log.info(f"No registered devices for {self.upn}")
            return

        device_data = [{
            "displayName": d.get("displayName"),
            "deviceId": d.get("deviceId"),
            "operatingSystem": d.get("operatingSystem"),
            "operatingSystemVersion": d.get("operatingSystemVersion"),
            "isManaged": d.get("isManaged"),
            "isCompliant": d.get("isCompliant"),
            "trustType": d.get("trustType"),
            "registrationDateTime": d.get("registrationDateTime"),
            "approximateLastSignInDateTime": d.get("approximateLastSignInDateTime"),
            "accountEnabled": d.get("accountEnabled"),
        } for d in devices]

        self.exporter.export("RegisteredDevices", device_data, self.user_folder)

        unmanaged = [d for d in device_data if not d["isManaged"]]
        if unmanaged:
            self.exporter.export("UnmanagedDevices", unmanaged, self.user_folder, investigate=True)
            log.investigate(f"Found {len(unmanaged)} unmanaged device(s) for {self.upn}")

    def get_app_role_assignments(self):
        log.info(f"=== Collecting App Role Assignments: {self.upn} ===")
        assignments = self.graph.get_all(f"users/{self.upn}/appRoleAssignments")
        if not assignments:
            return

        role_data = [{
            "appRoleId": a.get("appRoleId"),
            "principalDisplayName": a.get("principalDisplayName"),
            "resourceDisplayName": a.get("resourceDisplayName"),
            "resourceId": a.get("resourceId"),
            "createdDateTime": a.get("createdDateTime"),
        } for a in assignments]

        self.exporter.export("UserAppRoleAssignments", role_data, self.user_folder)

    def get_oauth_grants(self):
        log.info(f"=== Collecting User OAuth Grants: {self.upn} ===")
        grants = self.graph.get_all(f"users/{self.upn}/oauth2PermissionGrants")
        if not grants:
            return

        grant_data = [{
            "clientId": g.get("clientId"),
            "consentType": g.get("consentType"),
            "scope": g.get("scope"),
            "startDateTime": g.get("startDateTime"),
            "expiryDateTime": g.get("expiryDateTime"),
            "resourceId": g.get("resourceId"),
        } for g in grants]

        self.exporter.export("UserOAuthGrants", grant_data, self.user_folder)

        risky = [g for g in grant_data if any(s in (g.get("scope") or "") for s in DANGEROUS_SCOPES)]
        if risky:
            self.exporter.export("UserHighPrivilegeGrants", risky, self.user_folder, investigate=True)
            log.investigate(f"Found {len(risky)} high-privilege OAuth grant(s) for {self.upn}")

    def get_group_memberships(self):
        log.info(f"=== Collecting Group Memberships: {self.upn} ===")
        memberships = self.graph.get_all(f"users/{self.upn}/memberOf")
        if not memberships:
            return

        group_data = [{
            "displayName": m.get("displayName"),
            "id": m.get("id"),
            "type": m.get("@odata.type", ""),
            "description": (m.get("description") or "")[:200],
            "securityEnabled": m.get("securityEnabled"),
            "mailEnabled": m.get("mailEnabled"),
            "isAssignableToRole": m.get("isAssignableToRole"),
        } for m in memberships]

        self.exporter.export("GroupMemberships", group_data, self.user_folder)

        # Flag role-assignable groups
        role_groups = [g for g in group_data if g.get("isAssignableToRole")]
        if role_groups:
            self.exporter.export("RoleAssignableGroups", role_groups, self.user_folder, investigate=True)
            log.investigate(f"User {self.upn} is member of {len(role_groups)} role-assignable group(s)")

    def get_risk_detections(self):
        log.info(f"=== Collecting Risk Detections: {self.upn} ===")
        detections = self.graph.get_all(
            "identityProtection/riskDetections",
            params={"$filter": f"userPrincipalName eq '{self.upn}'"},
        )
        if not detections:
            log.info(f"No risk detections for {self.upn}")
            return

        risk_data = [{
            "id": d.get("id"),
            "riskEventType": d.get("riskEventType"),
            "riskLevel": d.get("riskLevel"),
            "riskState": d.get("riskState"),
            "riskDetail": d.get("riskDetail"),
            "detectedDateTime": d.get("detectedDateTime"),
            "lastUpdatedDateTime": d.get("lastUpdatedDateTime"),
            "ipAddress": d.get("ipAddress"),
            "location": json.dumps(d.get("location", {}), default=str),
            "source": d.get("source"),
            "detectionTimingType": d.get("detectionTimingType"),
            "activity": d.get("activity"),
            "tokenIssuerType": d.get("tokenIssuerType"),
        } for d in detections]

        self.exporter.export("RiskDetections", risk_data, self.user_folder, investigate=True)
        log.investigate(f"Found {len(risk_data)} risk detection(s) for {self.upn}",
                        mitre_ids=["T1078.004"])

    def get_mfa_methods(self):
        log.info(f"=== Collecting MFA / Auth Methods: {self.upn} ===")
        methods = self.graph.get_all(
            f"users/{self.upn}/authentication/methods", beta=True
        )
        if not methods:
            log.investigate(f"No authentication methods found for {self.upn} - potential MFA not configured",
                            mitre_ids=["T1556.006"])
            return

        method_data = [{
            "id": m.get("id"),
            "type": m.get("@odata.type", ""),
            "displayName": m.get("displayName", ""),
            "phoneNumber": m.get("phoneNumber", ""),
            "phoneType": m.get("phoneType", ""),
            "emailAddress": m.get("emailAddress", ""),
            "createdDateTime": m.get("createdDateTime", ""),
        } for m in methods]

        self.exporter.export("AuthenticationMethods", method_data, self.user_folder)

        # Check for weak methods only
        method_types = [m.get("@odata.type", "") for m in methods]
        strong_methods = [m for m in method_types if "fido2" in m.lower() or
                          "microsoftAuthenticator" in m or "windowsHello" in m.lower()]
        if not strong_methods:
            log.investigate(f"User {self.upn} has no phishing-resistant MFA methods",
                            mitre_ids=["T1556.006"])

    def get_non_interactive_sign_ins(self):
        log.info(f"=== Collecting Non-Interactive Sign-In Logs: {self.upn} ===")
        sign_ins = self.graph.get_all(
            "auditLogs/signIns",
            params={
                "$filter": f"userPrincipalName eq '{self.upn}' and signInEventTypes/any(t:t eq 'nonInteractiveUser')",
            },
            beta=True,
            max_records=2000,
        )
        if not sign_ins:
            return

        si_data = []
        for si in sign_ins:
            loc = si.get("location", {})
            status = si.get("status", {})
            si_data.append({
                "createdDateTime": si.get("createdDateTime"),
                "appDisplayName": si.get("appDisplayName"),
                "resourceDisplayName": si.get("resourceDisplayName"),
                "ipAddress": si.get("ipAddress"),
                "location": f"{loc.get('city', '')}, {loc.get('countryOrRegion', '')}",
                "statusCode": status.get("errorCode") if isinstance(status, dict) else "",
                "tokenIssuerType": si.get("tokenIssuerType"),
                "isInteractive": False,
            })

        self.exporter.export("NonInteractiveSignIns", si_data, self.user_folder)

    def get_sp_sign_ins(self):
        log.info(f"=== Collecting Service Principal Sign-Ins for User Apps: {self.upn} ===")
        # Get apps the user consented to and check their sign-in activity
        grants = self.graph.get_all(f"users/{self.upn}/oauth2PermissionGrants")
        if not grants:
            return

        sp_sign_ins = []
        for g in grants[:10]:  # Limit to avoid excessive API calls
            client_id = g.get("clientId", "")
            if not client_id:
                continue
            sp_si = self.graph.get_all(
                "auditLogs/signIns",
                params={
                    "$filter": f"appId eq '{client_id}'",
                    "$top": "50",
                },
                max_records=50,
            )
            for si in sp_si:
                sp_sign_ins.append({
                    "createdDateTime": si.get("createdDateTime"),
                    "appDisplayName": si.get("appDisplayName"),
                    "appId": si.get("appId"),
                    "ipAddress": si.get("ipAddress"),
                    "resourceDisplayName": si.get("resourceDisplayName"),
                    "servicePrincipalId": si.get("servicePrincipalId"),
                })

        if sp_sign_ins:
            self.exporter.export("UserAppSignInActivity", sp_sign_ins, self.user_folder)

    def get_auth_method_changes(self):
        log.info(f"=== Collecting Authentication Method Changes: {self.upn} ===")
        filter_str = (
            f"targetResources/any(t:t/userPrincipalName eq '{self.upn}') and ("
            "activityDisplayName eq 'User registered security info' or "
            "activityDisplayName eq 'User deleted security info' or "
            "activityDisplayName eq 'Admin registered security info' or "
            "activityDisplayName eq 'User registered all required security info' or "
            "activityDisplayName eq 'Reset user strong authentication' or "
            "activityDisplayName eq 'Admin updated security info')"
        )
        logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
        if not logs:
            return

        change_data = [{
            "activityDateTime": e.get("activityDateTime"),
            "activity": e.get("activityDisplayName"),
            "result": e.get("result"),
            "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
            "targetResources": json.dumps(e.get("targetResources", [])[:3], default=str)[:500],
        } for e in logs]

        self.exporter.export("AuthMethodChanges", change_data, self.user_folder, investigate=True)
        log.investigate(f"Found {len(change_data)} auth method change(s) for {self.upn}",
                        mitre_ids=["T1556.006"])

    def get_user_directory_roles(self):
        log.info(f"=== Collecting User Directory Role Memberships: {self.upn} ===")
        user_info = self.graph.get(f"users/{self.upn}")
        if not user_info:
            return
        user_id = user_info.get("id")
        if not user_id:
            return

        roles = self.graph.get_all(
            f"users/{user_id}/transitiveMemberOf/microsoft.graph.directoryRole"
        )
        if not roles:
            return

        role_data = [{
            "roleName": r.get("displayName"),
            "roleId": r.get("id"),
            "description": (r.get("description") or "")[:200],
        } for r in roles]

        self.exporter.export("UserDirectoryRoles", role_data, self.user_folder)

        admin_roles = [r for r in role_data if r["roleName"] in HIGH_PRIVILEGE_ROLES]
        if admin_roles:
            log.investigate(
                f"User {self.upn} has {len(admin_roles)} high-privilege role(s): "
                f"{', '.join(r['roleName'] for r in admin_roles)}",
                mitre_ids=["T1098.003"]
            )

    def get_recent_emails_metadata(self):
        log.info(f"=== Collecting Recent Email Metadata: {self.upn} ===")
        msgs = self.graph.get_all(
            f"users/{self.upn}/messages",
            params={
                "$select": "id,subject,from,toRecipients,ccRecipients,receivedDateTime,"
                           "sentDateTime,hasAttachments,importance,isRead,internetMessageHeaders",
                "$orderby": "receivedDateTime desc",
                "$top": "200",
            },
            max_records=200,
        )
        if not msgs:
            return

        msg_data = []
        suspicious_subjects = []
        for m in msgs:
            from_addr = ""
            from_info = m.get("from", {})
            if isinstance(from_info, dict):
                ea = from_info.get("emailAddress", {})
                if isinstance(ea, dict):
                    from_addr = ea.get("address", "")

            to_addrs = []
            for r in (m.get("toRecipients") or []):
                if isinstance(r, dict):
                    ea = r.get("emailAddress", {})
                    if isinstance(ea, dict):
                        to_addrs.append(ea.get("address", ""))

            entry = {
                "receivedDateTime": m.get("receivedDateTime"),
                "sentDateTime": m.get("sentDateTime"),
                "from": from_addr,
                "to": "; ".join(to_addrs[:5]),
                "subject": (m.get("subject") or "")[:200],
                "hasAttachments": m.get("hasAttachments"),
                "importance": m.get("importance"),
                "isRead": m.get("isRead"),
            }
            msg_data.append(entry)

            # Check for BEC-related subjects
            subj_lower = (m.get("subject") or "").lower()
            if any(kw in subj_lower for kw in BEC_SUSPICIOUS_SUBJECTS):
                suspicious_subjects.append(entry)

        self.exporter.export("RecentEmails", msg_data, self.user_folder)

        if suspicious_subjects:
            self.exporter.export("BEC_SuspiciousEmails", suspicious_subjects,
                                 self.user_folder, investigate=True)
            log.investigate(
                f"Found {len(suspicious_subjects)} email(s) with BEC-related subjects for {self.upn}",
                mitre_ids=["T1534", "T1566.002"]
            )

    def get_mail_folders(self):
        log.info(f"=== Collecting Mail Folder Structure: {self.upn} ===")
        folders = self.graph.get_all(f"users/{self.upn}/mailFolders",
                                     params={"$top": "100", "$select": "displayName,totalItemCount,unreadItemCount,childFolderCount"})
        if not folders:
            return

        folder_data = [{
            "displayName": f.get("displayName"),
            "totalItemCount": f.get("totalItemCount"),
            "unreadItemCount": f.get("unreadItemCount"),
            "childFolderCount": f.get("childFolderCount"),
        } for f in folders]

        self.exporter.export("MailFolders", folder_data, self.user_folder)

        # Flag unusual folders (RSS, hidden)
        suspicious_names = ["rss subscriptions", "rss feeds", "sync issues", "conflicts"]
        unusual = [f for f in folder_data if f["displayName"].lower() in suspicious_names and f["totalItemCount"] > 0]
        if unusual:
            log.warn(f"Unusual mail folders with items for {self.upn}: {', '.join(f['displayName'] for f in unusual)}")

    def get_mailbox_delegates(self):
        log.info(f"=== Collecting Mailbox Delegate Permissions: {self.upn} ===")
        # Check mailbox permissions via Graph
        perms = self.graph.get(f"users/{self.upn}/mailboxSettings")
        if not perms:
            return

        # Check for delegates
        delegates = self.graph.get_all(
            f"users/{self.upn}/mailFolders/inbox/permissions", beta=True
        )
        if delegates:
            delegate_data = [{
                "emailAddress": d.get("emailAddress", {}).get("address", "") if isinstance(d.get("emailAddress"), dict) else "",
                "role": d.get("role"),
                "isInsideOrganization": d.get("isInsideOrganization"),
                "allowedRoles": "; ".join(d.get("allowedRoles", []) if isinstance(d.get("allowedRoles"), list) else []),
            } for d in delegates]

            self.exporter.export("MailboxDelegates", delegate_data, self.user_folder, investigate=True)
            log.investigate(
                f"Found {len(delegate_data)} mailbox delegate permission(s) for {self.upn}",
                mitre_ids=["T1098.002"]
            )

    def get_onedrive_activity(self):
        log.info(f"=== Collecting OneDrive Recent Activity: {self.upn} ===")
        # Get recently modified files
        items = self.graph.get_all(
            f"users/{self.upn}/drive/recent",
            max_records=100,
        )
        if not items:
            return

        file_data = [{
            "name": i.get("name"),
            "webUrl": i.get("webUrl", "")[:200],
            "size": i.get("size"),
            "createdDateTime": i.get("createdDateTime"),
            "lastModifiedDateTime": i.get("lastModifiedDateTime"),
            "createdBy": (i.get("createdBy", {}) or {}).get("user", {}).get("displayName", ""),
            "lastModifiedBy": (i.get("lastModifiedBy", {}) or {}).get("user", {}).get("displayName", ""),
            "shared": bool(i.get("shared")),
        } for i in items]

        self.exporter.export("OneDriveRecentFiles", file_data, self.user_folder)

        # Flag large downloads or external sharing
        shared = [f for f in file_data if f["shared"]]
        if shared:
            log.investigate(
                f"Found {len(shared)} shared OneDrive file(s) for {self.upn}",
                mitre_ids=["T1530"]
            )


# ============================================================================
# BEC INVESTIGATION MODULE
# ============================================================================

class BECInvestigator:
    """Specialized Business Email Compromise investigation module."""

    def __init__(self, graph: GraphClient, exporter: DataExporter,
                 upn: str, start_date: datetime, end_date: datetime):
        self.graph = graph
        self.exporter = exporter
        self.upn = upn
        self.start_date = start_date
        self.end_date = end_date
        self.bec_folder = f"BEC_Investigation/{upn.replace('@', '_at_')}"

    def run_all(self):
        log.info("=" * 50)
        log.info(f"Starting BEC Investigation: {self.upn}")
        log.info("=" * 50)

        self.check_forwarding_rules()
        self.check_delegate_access()
        self.check_sent_items()
        self.check_deleted_items()
        self.check_consent_grants()
        self.check_password_changes()

        log.success(f"BEC investigation complete for {self.upn}")

    def check_forwarding_rules(self):
        log.info(f"=== BEC: Checking Email Forwarding: {self.upn} ===")
        # Check inbox rules for forwarding
        rules = self.graph.get_all(f"users/{self.upn}/mailFolders/inbox/messageRules")
        forwarding_rules = []
        for r in (rules or []):
            actions = r.get("actions", {})
            if not isinstance(actions, dict):
                continue
            forwards = []
            for key in ["forwardTo", "forwardAsAttachmentTo", "redirectTo"]:
                dests = actions.get(key) or []
                for d in dests:
                    if isinstance(d, dict):
                        addr = d.get("emailAddress", {}).get("address", "")
                        if addr:
                            forwards.append(addr)
            if forwards:
                forwarding_rules.append({
                    "ruleName": r.get("displayName"),
                    "isEnabled": r.get("isEnabled"),
                    "forwardingDestinations": "; ".join(forwards),
                    "deleteOriginal": actions.get("delete", False),
                    "markAsRead": actions.get("markAsRead", False),
                })

        if forwarding_rules:
            self.exporter.export("BEC_ForwardingRules", forwarding_rules, self.bec_folder, investigate=True)
            log.investigate(
                f"BEC: {len(forwarding_rules)} forwarding rule(s) found for {self.upn}",
                mitre_ids=["T1114.003"]
            )

        # Check SMTP forwarding at mailbox level
        settings = self.graph.get(f"users/{self.upn}/mailboxSettings")
        if settings:
            # Check for automatic forwarding
            auto_fwd = settings.get("automaticRepliesSetting", {})
            if auto_fwd.get("status") != "disabled":
                log.investigate(
                    f"BEC: Auto-reply enabled for {self.upn} - check for social engineering content",
                    mitre_ids=["T1114.003"]
                )

    def check_delegate_access(self):
        log.info(f"=== BEC: Checking Delegate Access: {self.upn} ===")
        # Search audit for delegation changes
        filter_str = (
            f"activityDisplayName eq 'Add delegate permission' or "
            f"activityDisplayName eq 'Add-MailboxPermission' or "
            f"activityDisplayName eq 'Set-Mailbox'"
        )
        logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
        relevant = [e for e in (logs or []) if self.upn.lower() in json.dumps(e.get("targetResources", []), default=str).lower()]

        if relevant:
            del_data = [{
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
                "targetResources": json.dumps(e.get("targetResources", []), default=str)[:500],
            } for e in relevant]

            self.exporter.export("BEC_DelegateChanges", del_data, self.bec_folder, investigate=True)
            log.investigate(
                f"BEC: {len(del_data)} delegation change(s) for {self.upn}",
                mitre_ids=["T1098.002"]
            )

    def check_sent_items(self):
        log.info(f"=== BEC: Analyzing Sent Items: {self.upn} ===")
        msgs = self.graph.get_all(
            f"users/{self.upn}/mailFolders/sentitems/messages",
            params={
                "$select": "subject,toRecipients,sentDateTime,hasAttachments,bodyPreview",
                "$orderby": "sentDateTime desc",
                "$top": "500",
            },
            max_records=500,
        )
        if not msgs:
            return

        suspicious = []
        for m in msgs:
            subj = (m.get("subject") or "").lower()
            body_preview = (m.get("bodyPreview") or "").lower()

            # BEC keywords in subject or body
            if any(kw in subj or kw in body_preview for kw in BEC_SUSPICIOUS_SUBJECTS):
                to_addrs = []
                for r in (m.get("toRecipients") or []):
                    if isinstance(r, dict):
                        ea = r.get("emailAddress", {})
                        if isinstance(ea, dict):
                            to_addrs.append(ea.get("address", ""))
                suspicious.append({
                    "sentDateTime": m.get("sentDateTime"),
                    "subject": (m.get("subject") or "")[:200],
                    "to": "; ".join(to_addrs[:5]),
                    "hasAttachments": m.get("hasAttachments"),
                    "bodyPreview": (m.get("bodyPreview") or "")[:300],
                })

        if suspicious:
            self.exporter.export("BEC_SuspiciousSentItems", suspicious, self.bec_folder, investigate=True)
            log.investigate(
                f"BEC: {len(suspicious)} suspicious sent email(s) from {self.upn}",
                mitre_ids=["T1534"]
            )

    def check_deleted_items(self):
        log.info(f"=== BEC: Checking Deleted Items Volume: {self.upn} ===")
        deleted_folder = self.graph.get(
            f"users/{self.upn}/mailFolders/deleteditems",
            params={"$select": "totalItemCount,unreadItemCount"}
        )
        if deleted_folder:
            count = deleted_folder.get("totalItemCount", 0)
            if count > 100:
                log.investigate(
                    f"BEC: {count} items in deleted items for {self.upn} - potential evidence destruction",
                    mitre_ids=["T1070.009"]
                )

    def check_consent_grants(self):
        log.info(f"=== BEC: Checking User Consent Grants: {self.upn} ===")
        grants = self.graph.get_all(f"users/{self.upn}/oauth2PermissionGrants")
        suspicious_grants = []
        for g in (grants or []):
            scope = g.get("scope", "")
            if any(s in scope for s in ["Mail.ReadWrite", "Mail.Send", "Mail.Read"]):
                sp = self.graph.get(f"servicePrincipals/{g['clientId']}")
                suspicious_grants.append({
                    "appName": sp.get("displayName") if sp else "Unknown",
                    "appId": sp.get("appId") if sp else g.get("clientId"),
                    "scope": scope,
                    "consentType": g.get("consentType"),
                })

        if suspicious_grants:
            self.exporter.export("BEC_MailAccessGrants", suspicious_grants, self.bec_folder, investigate=True)
            log.investigate(
                f"BEC: {len(suspicious_grants)} app(s) with mail access for {self.upn}",
                mitre_ids=["T1528"]
            )

    def check_password_changes(self):
        log.info(f"=== BEC: Checking Password/MFA Changes: {self.upn} ===")
        filter_str = (
            f"targetResources/any(t:t/userPrincipalName eq '{self.upn}') and ("
            "activityDisplayName eq 'Reset user password' or "
            "activityDisplayName eq 'Change user password' or "
            "activityDisplayName eq 'Reset password (by admin)' or "
            "activityDisplayName eq 'User registered security info' or "
            "activityDisplayName eq 'User deleted security info')"
        )
        logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
        if logs:
            pwd_data = [{
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
                "result": e.get("result"),
            } for e in logs]

            self.exporter.export("BEC_CredentialChanges", pwd_data, self.bec_folder, investigate=True)
            log.investigate(
                f"BEC: {len(pwd_data)} password/MFA change(s) for {self.upn}",
                mitre_ids=["T1098", "T1556.006"]
            )


# ============================================================================
# SHAREPOINT / ONEDRIVE INVESTIGATION
# ============================================================================

class SharePointInvestigator:
    """Investigate SharePoint and OneDrive activity for data exfiltration."""

    def __init__(self, graph: GraphClient, exporter: DataExporter,
                 start_date: datetime, end_date: datetime):
        self.graph = graph
        self.exporter = exporter
        self.start_date = start_date
        self.end_date = end_date

    def run_all(self):
        log.info("=" * 50)
        log.info("Starting SharePoint/OneDrive Investigation")
        log.info("=" * 50)

        self.get_sites()
        self.get_external_sharing()
        self.get_sharepoint_audit()

        log.success("SharePoint/OneDrive investigation complete")

    def get_sites(self):
        log.info("=== Collecting SharePoint Sites ===")
        sites = self.graph.get_all("sites?search=*", max_records=500)
        if not sites:
            return

        site_data = [{
            "displayName": s.get("displayName"),
            "webUrl": s.get("webUrl", "")[:200],
            "id": s.get("id"),
            "createdDateTime": s.get("createdDateTime"),
            "lastModifiedDateTime": s.get("lastModifiedDateTime"),
            "isPersonalSite": s.get("isPersonalSite", False),
        } for s in sites]

        self.exporter.export("SharePointSites", site_data, "SharePoint")

    def get_external_sharing(self):
        log.info("=== Checking External Sharing Configuration ===")
        # Check for sharing links and permissions
        filter_str = (
            "activityDisplayName eq 'SharingSet' or "
            "activityDisplayName eq 'AnonymousLinkCreated' or "
            "activityDisplayName eq 'CompanyLinkCreated' or "
            "activityDisplayName eq 'SharingInvitationCreated'"
        )
        logs = self.graph.get_all("auditLogs/directoryAudits", params={"$filter": filter_str})
        if logs:
            share_data = [{
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
                "targetResources": json.dumps(e.get("targetResources", []), default=str)[:500],
            } for e in logs]

            self.exporter.export("ExternalSharingActivity", share_data, "SharePoint", investigate=True)
            log.investigate(f"Found {len(share_data)} external sharing event(s)",
                            mitre_ids=["T1567", "T1213.002"])

    def get_sharepoint_audit(self):
        log.info("=== Collecting SharePoint Audit Activity ===")
        sp_ops = [
            "FileDownloaded", "FileUploaded", "FileDeleted",
            "FileModified", "FileAccessed", "FileMoved",
            "FolderCreated", "FolderDeleted",
        ]
        filter_parts = " or ".join(f"activityDisplayName eq '{op}'" for op in sp_ops)
        logs = self.graph.get_all(
            "auditLogs/directoryAudits",
            params={"$filter": filter_parts},
            max_records=5000,
        )
        if logs:
            sp_data = [{
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
                "targetResources": json.dumps(e.get("targetResources", []), default=str)[:500],
            } for e in logs]

            self.exporter.export("SharePointAuditLog", sp_data, "SharePoint")

            # High-volume download detection
            downloads = [e for e in logs if e.get("activityDisplayName") == "FileDownloaded"]
            if len(downloads) > 100:
                user_counts = Counter(
                    e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "")
                    for e in downloads
                )
                for user, count in user_counts.most_common(5):
                    if count > 50:
                        log.investigate(
                            f"High-volume file downloads: {user} downloaded {count} files",
                            mitre_ids=["T1530", "T1567"]
                        )


# ============================================================================
# TEAMS INVESTIGATION
# ============================================================================

class TeamsInvestigator:
    """Investigate Microsoft Teams activity for suspicious behavior."""

    def __init__(self, graph: GraphClient, exporter: DataExporter):
        self.graph = graph
        self.exporter = exporter

    def run_all(self):
        log.info("=" * 50)
        log.info("Starting Teams Investigation")
        log.info("=" * 50)

        self.get_teams()
        self.get_teams_apps()

        log.success("Teams investigation complete")

    def get_teams(self):
        log.info("=== Collecting Teams ===")
        teams = self.graph.get_all("groups", params={
            "$filter": "resourceProvisioningOptions/Any(x:x eq 'Team')",
            "$select": "id,displayName,description,createdDateTime,visibility,mail"
        })
        if not teams:
            return

        team_data = [{
            "displayName": t.get("displayName"),
            "id": t.get("id"),
            "description": (t.get("description") or "")[:200],
            "createdDateTime": t.get("createdDateTime"),
            "visibility": t.get("visibility"),
            "mail": t.get("mail"),
        } for t in teams]

        self.exporter.export("Teams", team_data, "Teams")

        # Flag public teams
        public_teams = [t for t in team_data if t["visibility"] == "Public"]
        if public_teams:
            log.warn(f"Found {len(public_teams)} public Team(s) - verify external access settings")

    def get_teams_apps(self):
        log.info("=== Collecting Tenant-Wide Teams Apps ===")
        apps = self.graph.get_all("appCatalogs/teamsApps",
                                   params={"$filter": "distributionMethod eq 'sideloaded'"})
        if not apps:
            log.info("No sideloaded Teams apps found")
            return

        app_data = [{
            "displayName": a.get("displayName"),
            "id": a.get("id"),
            "distributionMethod": a.get("distributionMethod"),
            "externalId": a.get("externalId"),
        } for a in apps]

        self.exporter.export("SideloadedTeamsApps", app_data, "Teams", investigate=True)
        log.investigate(f"Found {len(app_data)} sideloaded Teams app(s)",
                        mitre_ids=["T1137.006"])


# ============================================================================
# UNIFIED TIMELINE GENERATOR
# ============================================================================

class TimelineGenerator:
    """Generate a unified chronological timeline across all data sources."""

    def __init__(self, exporter: DataExporter):
        self.exporter = exporter
        self.events: list[dict] = []

    def add_sign_ins(self, sign_ins: list[dict]):
        for si in sign_ins:
            status = si.get("status", {})
            err = status.get("errorCode", 0) if isinstance(status, dict) else 0
            self.events.append({
                "timestamp": si.get("createdDateTime", ""),
                "source": "SignIn",
                "category": "Authentication",
                "user": si.get("userPrincipalName", ""),
                "action": f"Sign-in to {si.get('appDisplayName', 'Unknown')}",
                "result": "Success" if not err else f"Failure ({err})",
                "ip": si.get("ipAddress", ""),
                "detail": f"Client: {si.get('clientAppUsed', '')} | "
                          f"Risk: {si.get('riskLevelDuringSignIn', 'none')}",
            })

    def add_audit_logs(self, audits: list[dict]):
        for a in audits:
            user = a.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "")
            if not user:
                user = a.get("initiatedBy", {}).get("app", {}).get("displayName", "System")
            self.events.append({
                "timestamp": a.get("activityDateTime", ""),
                "source": "AuditLog",
                "category": a.get("category", ""),
                "user": user,
                "action": a.get("activityDisplayName", ""),
                "result": a.get("result", ""),
                "ip": "",
                "detail": a.get("correlationId", ""),
            })

    def add_alerts(self, alerts: list[dict]):
        for a in alerts:
            self.events.append({
                "timestamp": a.get("createdDateTime", ""),
                "source": "SecurityAlert",
                "category": a.get("category", ""),
                "user": "",
                "action": a.get("title", ""),
                "result": a.get("severity", ""),
                "ip": "",
                "detail": (a.get("description", "") or "")[:200],
            })

    def add_risk_detections(self, detections: list[dict]):
        for d in detections:
            self.events.append({
                "timestamp": d.get("detectedDateTime", ""),
                "source": "RiskDetection",
                "category": d.get("riskEventType", ""),
                "user": d.get("userPrincipalName", ""),
                "action": d.get("riskEventType", ""),
                "result": d.get("riskLevel", ""),
                "ip": d.get("ipAddress", ""),
                "detail": d.get("riskDetail", ""),
            })

    def add_custom(self, timestamp: str, source: str, category: str,
                   user: str, action: str, result: str = "", detail: str = ""):
        self.events.append({
            "timestamp": timestamp,
            "source": source,
            "category": category,
            "user": user,
            "action": action,
            "result": result,
            "ip": "",
            "detail": detail,
        })

    def generate(self):
        """Sort and export the unified timeline."""
        if not self.events:
            return

        sorted_events = sorted(self.events, key=lambda x: x.get("timestamp", ""))
        self.exporter.export("UnifiedTimeline", sorted_events, "Timeline")

        # User activity summary
        user_counts = Counter(e["user"] for e in sorted_events if e["user"])
        user_summary = [{"user": u, "eventCount": c} for u, c in user_counts.most_common(50)]
        self.exporter.export("TimelineUserSummary", user_summary, "Timeline")

        # Source summary
        source_counts = Counter(e["source"] for e in sorted_events)
        source_summary = [{"source": s, "eventCount": c} for s, c in source_counts.most_common()]
        self.exporter.export("TimelineSourceSummary", source_summary, "Timeline")

        # Hourly activity heatmap
        hourly: dict[int, int] = defaultdict(int)
        for e in sorted_events:
            dt = parse_iso_dt(e.get("timestamp"))
            if dt:
                hourly[dt.hour] += 1
        heatmap = [{"hour": h, "eventCount": hourly.get(h, 0)} for h in range(24)]
        self.exporter.export("TimelineHourlyHeatmap", heatmap, "Timeline")

        log.success(f"Unified timeline generated: {len(sorted_events)} events")


# ============================================================================
# USER-AGENT / SESSION / COUNTRY ANALYSIS
# ============================================================================

class SignInAnalyzer:
    """Advanced sign-in analysis: user-agent clustering, country anomaly, session correlation."""

    def __init__(self, exporter: DataExporter):
        self.exporter = exporter

    def analyze_user_agents(self, sign_ins: list[dict]):
        """Cluster and analyze user-agent strings for anomalies."""
        ua_groups: dict[str, list] = defaultdict(list)
        for si in sign_ins:
            device = si.get("deviceDetail", {}) or {}
            browser = device.get("browser", "Unknown")
            os_name = device.get("operatingSystem", "Unknown")
            ua_key = f"{browser} | {os_name}"
            ua_groups[ua_key].append(si)

        ua_data = []
        for ua, events in sorted(ua_groups.items(), key=lambda x: len(x[1]), reverse=True):
            users = set(e.get("userPrincipalName", "") for e in events)
            ips = set(e.get("ipAddress", "") for e in events)
            times = [e.get("createdDateTime", "") for e in events if e.get("createdDateTime")]
            ua_data.append({
                "userAgent": ua,
                "count": len(events),
                "uniqueUsers": len(users),
                "uniqueIPs": len(ips),
                "users": "; ".join(sorted(users)[:10]),
                "firstSeen": min(times) if times else "",
                "lastSeen": max(times) if times else "",
            })

        if ua_data:
            self.exporter.export("UserAgentAnalysis", ua_data, "Analysis")

            # Flag unusual user agents (seen very few times)
            rare = [ua for ua in ua_data if ua["count"] <= 2 and ua["uniqueUsers"] == 1]
            if rare:
                self.exporter.export("RareUserAgents", rare, "Analysis", investigate=True)
                log.investigate(f"Found {len(rare)} rare user-agent combination(s)")

    def analyze_countries(self, sign_ins: list[dict]):
        """Analyze sign-in countries for anomalies."""
        country_groups: dict[str, list] = defaultdict(list)
        for si in sign_ins:
            loc = si.get("location", {}) if isinstance(si.get("location"), dict) else {}
            country = loc.get("countryOrRegion", "Unknown")
            country_groups[country].append(si)

        country_data = []
        for country, events in sorted(country_groups.items(), key=lambda x: len(x[1]), reverse=True):
            users = set(e.get("userPrincipalName", "") for e in events)
            success = sum(1 for e in events if not (isinstance(e.get("status"), dict) and
                          e.get("status", {}).get("errorCode")))
            failed = len(events) - success
            times = [e.get("createdDateTime", "") for e in events if e.get("createdDateTime")]
            country_data.append({
                "country": country,
                "totalSignIns": len(events),
                "successfulSignIns": success,
                "failedSignIns": failed,
                "uniqueUsers": len(users),
                "failureRate": round(failed / len(events) * 100, 1) if events else 0,
                "firstSeen": min(times) if times else "",
                "lastSeen": max(times) if times else "",
            })

        if country_data:
            self.exporter.export("CountryAnalysis", country_data, "Analysis")

            # Flag countries with high failure rates (potential attack origins)
            suspicious_countries = [c for c in country_data
                                     if c["failureRate"] > 80 and c["totalSignIns"] >= 5]
            if suspicious_countries:
                self.exporter.export("SuspiciousCountries", suspicious_countries,
                                     "Analysis", investigate=True)
                for c in suspicious_countries:
                    log.investigate(
                        f"Country {c['country']}: {c['failureRate']}% failure rate "
                        f"({c['failedSignIns']}/{c['totalSignIns']} sign-ins)",
                        mitre_ids=["T1110.003"]
                    )

    def analyze_sessions(self, sign_ins: list[dict]):
        """Correlate sign-in sessions by correlationId."""
        session_groups: dict[str, list] = defaultdict(list)
        for si in sign_ins:
            cid = si.get("correlationId", "")
            if cid:
                session_groups[cid].append(si)

        # Find multi-step sessions (potential attack chains)
        multi_step = {cid: events for cid, events in session_groups.items() if len(events) >= 3}

        if multi_step:
            session_data = []
            for cid, events in sorted(multi_step.items(),
                                        key=lambda x: len(x[1]), reverse=True)[:50]:
                sorted_events = sorted(events, key=lambda x: x.get("createdDateTime", ""))
                apps = set(e.get("appDisplayName", "") for e in sorted_events)
                resources = set(e.get("resourceDisplayName", "") for e in sorted_events)
                session_data.append({
                    "correlationId": cid,
                    "eventCount": len(sorted_events),
                    "user": sorted_events[0].get("userPrincipalName", ""),
                    "startTime": sorted_events[0].get("createdDateTime", ""),
                    "endTime": sorted_events[-1].get("createdDateTime", ""),
                    "applications": "; ".join(apps),
                    "resources": "; ".join(resources),
                    "ipAddress": sorted_events[0].get("ipAddress", ""),
                })

            self.exporter.export("SessionCorrelation", session_data, "Analysis")

    def analyze_app_usage(self, sign_ins: list[dict]):
        """Analyze application usage patterns."""
        app_groups: dict[str, list] = defaultdict(list)
        for si in sign_ins:
            app = si.get("appDisplayName", "Unknown")
            app_groups[app].append(si)

        app_data = []
        for app, events in sorted(app_groups.items(), key=lambda x: len(x[1]), reverse=True):
            users = set(e.get("userPrincipalName", "") for e in events)
            ips = set(e.get("ipAddress", "") for e in events if e.get("ipAddress"))
            success = sum(1 for e in events if not (isinstance(e.get("status"), dict) and
                          e.get("status", {}).get("errorCode")))
            app_data.append({
                "application": app,
                "totalSignIns": len(events),
                "successfulSignIns": success,
                "uniqueUsers": len(users),
                "uniqueIPs": len(ips),
            })

        if app_data:
            self.exporter.export("ApplicationUsageAnalysis", app_data, "Analysis")


# ============================================================================
# KQL QUERY GENERATOR
# ============================================================================

class KQLQueryGenerator:
    """Generate Microsoft Sentinel KQL queries from investigation findings."""

    def __init__(self, output_root: str):
        self.output_root = output_root
        self.queries: list[dict] = []

    def add_ip_query(self, ip: str):
        self.queries.append({
            "name": f"Sign-ins from IP {ip}",
            "description": f"All sign-in activity from suspicious IP {ip}",
            "query": f"""SigninLogs
| where IPAddress == "{ip}"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          LocationDetails, ResultType, ResultDescription, ClientAppUsed
| sort by TimeGenerated desc""",
        })
        self.queries.append({
            "name": f"AAD Audit from IP {ip}",
            "description": f"Directory audit events correlated with IP {ip}",
            "query": f"""SigninLogs
| where IPAddress == "{ip}"
| project CorrelationId
| join kind=inner (AuditLogs) on CorrelationId
| project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources
| sort by TimeGenerated desc""",
        })

    def add_user_query(self, upn: str):
        self.queries.append({
            "name": f"All activity for {upn}",
            "description": f"Comprehensive activity timeline for {upn}",
            "query": f"""let user = "{upn}";
SigninLogs
| where UserPrincipalName =~ user
| project TimeGenerated, Type="SignIn", Operation=AppDisplayName,
          Result=tostring(ResultType), IPAddress, Details=ClientAppUsed
| union (
    AuditLogs
    | where InitiatedBy.user.userPrincipalName =~ user
    | project TimeGenerated, Type="Audit", Operation=OperationName,
              Result, IPAddress="", Details=tostring(TargetResources)
)
| sort by TimeGenerated desc""",
        })

    def add_forwarding_query(self):
        self.queries.append({
            "name": "Email forwarding rule changes",
            "description": "Detect inbox rule changes that create forwarding",
            "query": """AuditLogs
| where OperationName in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend Parameters = tostring(TargetResources[0].modifiedProperties)
| where Parameters contains "ForwardTo" or Parameters contains "RedirectTo"
        or Parameters contains "ForwardAsAttachmentTo"
| project TimeGenerated, InitiatedBy.user.userPrincipalName,
          OperationName, Parameters
| sort by TimeGenerated desc""",
        })

    def add_consent_query(self):
        self.queries.append({
            "name": "OAuth consent grants",
            "description": "Detect application consent grant events",
            "query": """AuditLogs
| where OperationName == "Consent to application"
| extend AppName = TargetResources[0].displayName
| extend ConsentedBy = InitiatedBy.user.userPrincipalName
| project TimeGenerated, ConsentedBy, AppName, Result, TargetResources
| sort by TimeGenerated desc""",
        })

    def add_impossible_travel_query(self):
        self.queries.append({
            "name": "Impossible travel detection",
            "description": "Detect sign-ins from geographically impossible locations",
            "query": """SigninLogs
| where ResultType == 0
| extend City = LocationDetails.city, Country = LocationDetails.countryOrRegion,
         Lat = toreal(LocationDetails.geoCoordinates.latitude),
         Lon = toreal(LocationDetails.geoCoordinates.longitude)
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country, Lat, Lon
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevLat = prev(Lat), PrevLon = prev(Lon),
         PrevUser = prev(UserPrincipalName), PrevCountry = prev(Country)
| where UserPrincipalName == PrevUser
| extend TimeDiffHours = datetime_diff('hour', TimeGenerated, PrevTime)
| where Country != PrevCountry and TimeDiffHours < 2
| project TimeGenerated, UserPrincipalName, IPAddress,
          FromCountry=PrevCountry, ToCountry=Country, TimeDiffHours""",
        })

    def add_password_spray_query(self):
        self.queries.append({
            "name": "Password spray detection",
            "description": "Detect distributed brute force across multiple accounts",
            "query": """SigninLogs
| where ResultType in ("50126", "50053", "50055")
| summarize FailedUsers=dcount(UserPrincipalName),
            FailedAttempts=count(),
            Users=make_set(UserPrincipalName, 20)
  by IPAddress, bin(TimeGenerated, 1h)
| where FailedUsers >= 5 and FailedAttempts >= 10
| sort by FailedAttempts desc""",
        })

    def add_legacy_auth_query(self):
        self.queries.append({
            "name": "Legacy authentication usage",
            "description": "Detect use of legacy authentication protocols",
            "query": """SigninLogs
| where ClientAppUsed in ("Authenticated SMTP", "Autodiscover",
         "Exchange ActiveSync", "Exchange Online PowerShell",
         "IMAP4", "MAPI Over HTTP", "Offline Address Book",
         "Other clients", "POP3", "Reporting Web Services")
| summarize Count=count() by UserPrincipalName, ClientAppUsed, IPAddress
| sort by Count desc""",
        })

    def generate_all_default(self):
        """Generate a comprehensive set of default hunting queries."""
        self.add_forwarding_query()
        self.add_consent_query()
        self.add_impossible_travel_query()
        self.add_password_spray_query()
        self.add_legacy_auth_query()

    def export(self):
        """Export all KQL queries."""
        if not self.queries:
            return

        kql_dir = os.path.join(self.output_root, "KQL_Queries")
        os.makedirs(kql_dir, exist_ok=True)

        # Individual query files
        for i, q in enumerate(self.queries):
            safe_name = re.sub(r'[^\w\-]', '_', q["name"])[:60]
            path = os.path.join(kql_dir, f"{i+1:02d}_{safe_name}.kql")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"// {q['name']}\n")
                f.write(f"// {q['description']}\n")
                f.write(f"// Generated by VCD Cloud Investigator v{VERSION}\n\n")
                f.write(q["query"])

        # Combined query file
        combined_path = os.path.join(kql_dir, "ALL_QUERIES.kql")
        with open(combined_path, "w", encoding="utf-8") as f:
            f.write(f"// VCD Cloud Investigator - Sentinel Hunting Queries\n")
            f.write(f"// Generated: {datetime.now().isoformat()}\n")
            f.write(f"// Total queries: {len(self.queries)}\n\n")
            for q in self.queries:
                f.write(f"// {'=' * 70}\n")
                f.write(f"// {q['name']}\n")
                f.write(f"// {q['description']}\n")
                f.write(f"// {'=' * 70}\n\n")
                f.write(q["query"])
                f.write("\n\n")

        log.success(f"Generated {len(self.queries)} KQL hunting queries in {kql_dir}")


# ============================================================================
# REMEDIATION RECOMMENDATIONS ENGINE
# ============================================================================

class RemediationEngine:
    """Generate actionable remediation recommendations from findings."""

    RECOMMENDATIONS: dict[str, dict] = {
        "VCD-SI-001": {
            "title": "Password Spray Attack Detected",
            "priority": "CRITICAL",
            "actions": [
                "Block the source IP address(es) in Conditional Access",
                "Reset passwords for any successfully compromised accounts",
                "Enable Azure AD Smart Lockout",
                "Implement Conditional Access policies requiring MFA",
                "Review sign-in logs for successful authentications from the same IP",
                "Consider implementing Azure AD Password Protection",
            ],
        },
        "VCD-SI-002": {
            "title": "Legacy Authentication Protocol Usage",
            "priority": "HIGH",
            "actions": [
                "Create Conditional Access policy to block legacy authentication",
                "Identify and migrate applications using legacy auth to modern auth",
                "Disable legacy auth protocols at the tenant level",
                "Monitor for new legacy auth usage after blocking",
            ],
        },
        "VCD-SI-003": {
            "title": "MFA Fatigue Attack",
            "priority": "CRITICAL",
            "actions": [
                "Reset the user's password immediately",
                "Revoke all active sessions and refresh tokens",
                "Switch to number-matching or FIDO2 for MFA",
                "Disable simple push notifications",
                "Investigate all actions taken during the compromised session",
            ],
        },
        "VCD-SI-006": {
            "title": "Impossible Travel Detected",
            "priority": "HIGH",
            "actions": [
                "Verify with the user whether both sign-ins are legitimate",
                "Check for VPN usage that could explain location discrepancy",
                "If unauthorized, reset password and revoke sessions",
                "Review actions taken from the suspicious location",
                "Enable Conditional Access with named locations",
            ],
        },
        "VCD-IR-001": {
            "title": "Email Forwarding Rule",
            "priority": "HIGH",
            "actions": [
                "Disable or delete the forwarding rule immediately",
                "Notify the user and verify if the rule is legitimate",
                "Check for other indicators of compromise on the account",
                "Review emails already forwarded to the external address",
                "Implement mail flow rules to block external auto-forwarding",
            ],
        },
        "VCD-IR-002": {
            "title": "Evidence Hiding Inbox Rule",
            "priority": "CRITICAL",
            "actions": [
                "Delete the malicious rule immediately",
                "Assume the account is compromised - full IR response",
                "Reset password and revoke all sessions",
                "Search for lateral movement from the account",
                "Review Deleted Items and Recoverable Items folders",
                "Check for other persistence mechanisms (OAuth apps, delegates)",
            ],
        },
        "VCD-APP-001": {
            "title": "Admin-Consented Dangerous Permissions",
            "priority": "CRITICAL",
            "actions": [
                "Review and remove unnecessary admin consent grants",
                "Verify the application is legitimate and from a trusted publisher",
                "Restrict user consent to verified publishers only",
                "Implement admin consent workflow",
                "Audit all admin consent grants regularly",
            ],
        },
        "VCD-ROLE-001": {
            "title": "Global Admin Role Assignment",
            "priority": "CRITICAL",
            "actions": [
                "Verify the assignment was authorized",
                "Implement PIM for just-in-time Global Admin access",
                "Ensure all Global Admins have phishing-resistant MFA",
                "Limit the number of permanent Global Admins to 2-4",
                "Create break-glass accounts with proper monitoring",
            ],
        },
        "VCD-FED-001": {
            "title": "Federated Domain / Golden SAML Risk",
            "priority": "HIGH",
            "actions": [
                "Verify federation configuration is legitimate",
                "Rotate SAML token signing certificates",
                "Monitor for anomalous SAML token usage",
                "Implement Conditional Access for federated sign-ins",
                "Consider migrating to Managed authentication",
            ],
        },
        "VCD-CA-001": {
            "title": "No Conditional Access Policies",
            "priority": "CRITICAL",
            "actions": [
                "Implement baseline Conditional Access policies immediately",
                "Require MFA for all users",
                "Block legacy authentication",
                "Require compliant devices for access",
                "Implement risk-based Conditional Access",
            ],
        },
    }

    def __init__(self, exporter: DataExporter, detections: list[dict]):
        self.exporter = exporter
        self.detections = detections

    def generate(self):
        """Generate remediation recommendations based on detections."""
        if not self.detections:
            return

        recommendations = []
        seen_rules = set()

        for det in self.detections:
            rule_id = det.get("ruleId", "")
            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)

            rec = self.RECOMMENDATIONS.get(rule_id)
            if rec:
                recommendations.append({
                    "ruleId": rule_id,
                    "title": rec["title"],
                    "priority": rec["priority"],
                    "finding": det.get("detail", ""),
                    "actions": "\n".join(f"  {i+1}. {a}" for i, a in enumerate(rec["actions"])),
                })

        if recommendations:
            self.exporter.export("RemediationRecommendations", recommendations, "Remediation")

            # Generate markdown report
            md_lines = [
                "# VCD Cloud Investigator - Remediation Recommendations\n",
                f"Generated: {datetime.now().isoformat()}\n",
                f"Total Recommendations: {len(recommendations)}\n\n",
                "---\n",
            ]
            for rec in sorted(recommendations, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["priority"], 3)):
                md_lines.append(f"\n## [{rec['priority']}] {rec['title']}\n")
                md_lines.append(f"**Rule:** {rec['ruleId']}\n")
                md_lines.append(f"**Finding:** {rec['finding']}\n\n")
                md_lines.append("**Remediation Steps:**\n")
                md_lines.append(rec["actions"] + "\n")
                md_lines.append("\n---\n")

            rem_dir = os.path.join(self.exporter.output_root, "Remediation")
            os.makedirs(rem_dir, exist_ok=True)
            md_path = os.path.join(rem_dir, "RemediationReport.md")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write("".join(md_lines))

            log.success(f"Generated {len(recommendations)} remediation recommendation(s)")


# ============================================================================
# STIX/TAXII IOC EXPORT
# ============================================================================

class STIXExporter:
    """Export IOCs in STIX 2.1 format for threat intelligence sharing."""

    def __init__(self, output_root: str, investigation_id: str):
        self.output_root = output_root
        self.investigation_id = investigation_id

    def export(self, iocs: dict[str, set]):
        """Export IOCs as STIX 2.1 bundle."""
        stix_objects = []

        # Identity (the tool)
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": "VCD Cloud Investigator",
            "identity_class": "tool",
        }
        stix_objects.append(identity)

        # IP indicators
        for ip in iocs.get("ip_addresses", set()):
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"Suspicious IP: {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "labels": ["malicious-activity"],
                "created_by_ref": identity["id"],
            }
            stix_objects.append(indicator)

        # Email indicators
        for email in iocs.get("email_addresses", set()):
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"Suspicious Email: {email}",
                "pattern": f"[email-addr:value = '{email}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "labels": ["malicious-activity"],
                "created_by_ref": identity["id"],
            }
            stix_objects.append(indicator)

        # Domain indicators
        for domain in iocs.get("domains", set()):
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"Suspicious Domain: {domain}",
                "pattern": f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "labels": ["malicious-activity"],
                "created_by_ref": identity["id"],
            }
            stix_objects.append(indicator)

        if len(stix_objects) <= 1:  # Only identity, no IOCs
            return

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects,
        }

        stix_dir = os.path.join(self.output_root, "IOCs")
        os.makedirs(stix_dir, exist_ok=True)
        stix_path = os.path.join(stix_dir, "iocs_stix2.1.json")
        with open(stix_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, default=str)

        log.success(f"STIX 2.1 bundle exported: {len(stix_objects) - 1} indicators")


# ============================================================================
# IP INVESTIGATION
# ============================================================================

class IPInvestigator:
    """Searches all tenant activity from specific IP addresses."""

    def __init__(self, graph: GraphClient, exporter: DataExporter,
                 ip: str, start_date: datetime, end_date: datetime):
        self.graph = graph
        self.exporter = exporter
        self.ip = ip
        self.start_date = start_date
        self.end_date = end_date
        self.ip_folder = f"IP_Investigation/{ip.replace('.', '_').replace(':', '_')}"

    def run_all(self):
        log.info("=" * 50)
        log.info(f"Starting IP Investigation: {self.ip}")
        log.info("=" * 50)

        self.search_sign_ins()
        self.search_audit_logs()
        self.search_risk_detections()

        log.success(f"IP investigation complete for {self.ip}")

    def search_sign_ins(self):
        log.info(f"=== Searching Sign-In Logs for IP: {self.ip} ===")
        sign_ins = self.graph.get_all(
            "auditLogs/signIns",
            params={"$filter": f"ipAddress eq '{self.ip}'"},
            max_records=5000,
        )
        if not sign_ins:
            log.info(f"No sign-in logs found for IP {self.ip}")
            return

        si_data = []
        for si in sign_ins:
            loc = si.get("location", {})
            status = si.get("status", {})
            device = si.get("deviceDetail", {})

            si_data.append({
                "createdDateTime": si.get("createdDateTime"),
                "userPrincipalName": si.get("userPrincipalName"),
                "appDisplayName": si.get("appDisplayName"),
                "clientAppUsed": si.get("clientAppUsed"),
                "ipAddress": si.get("ipAddress"),
                "location": f"{loc.get('city', '')}, {loc.get('state', '')}, {loc.get('countryOrRegion', '')}",
                "statusCode": status.get("errorCode"),
                "riskLevel": si.get("riskLevelDuringSignIn"),
                "isInteractive": si.get("isInteractive"),
                "deviceOS": device.get("operatingSystem"),
                "deviceBrowser": device.get("browser"),
            })

        self.exporter.export(f"SignIns_{self.ip}", si_data, self.ip_folder)

        # User summary
        user_groups: dict[str, list] = {}
        for s in si_data:
            upn = s.get("userPrincipalName", "Unknown")
            user_groups.setdefault(upn, []).append(s)

        user_summary = []
        for upn, entries in sorted(user_groups.items(), key=lambda x: len(x[1]), reverse=True):
            times = [e["createdDateTime"] for e in entries if e["createdDateTime"]]
            user_summary.append({
                "userPrincipalName": upn,
                "count": len(entries),
                "apps": "; ".join(set(e["appDisplayName"] or "" for e in entries)),
                "firstSeen": min(times) if times else "",
                "lastSeen": max(times) if times else "",
            })

        self.exporter.export(f"UserSummary_{self.ip}", user_summary, self.ip_folder, investigate=True)
        log.investigate(f"Found {len(si_data)} sign-in(s) from {self.ip} across {len(user_summary)} user(s)")

    def search_audit_logs(self):
        log.info(f"=== Searching Audit Logs for IP: {self.ip} ===")
        # Directory audit logs don't directly filter by IP, but we can check
        # risk detections and sign-ins. This searches for any audit activity
        # correlated with the IP through sign-in correlationIds.
        sign_ins = self.graph.get_all(
            "auditLogs/signIns",
            params={"$filter": f"ipAddress eq '{self.ip}'", "$select": "correlationId"},
            max_records=500,
        )
        if not sign_ins:
            return

        correlation_ids = list(set(s.get("correlationId") for s in sign_ins if s.get("correlationId")))[:20]

        all_audit = []
        for cid in correlation_ids:
            logs = self.graph.get_all(
                "auditLogs/directoryAudits",
                params={"$filter": f"correlationId eq '{cid}'"},
            )
            all_audit.extend(logs)

        if all_audit:
            audit_data = [{
                "activityDateTime": e.get("activityDateTime"),
                "activity": e.get("activityDisplayName"),
                "result": e.get("result"),
                "initiatedBy": e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", ""),
                "category": e.get("category"),
                "correlationId": e.get("correlationId"),
            } for e in all_audit]

            self.exporter.export(f"CorrelatedAuditLog_{self.ip}", audit_data, self.ip_folder, investigate=True)
            log.investigate(f"Found {len(audit_data)} correlated audit log entries for IP {self.ip}")

    def search_risk_detections(self):
        log.info(f"=== Searching Risk Detections for IP: {self.ip} ===")
        detections = self.graph.get_all(
            "identityProtection/riskDetections",
            params={"$filter": f"ipAddress eq '{self.ip}'"},
        )
        if not detections:
            log.info(f"No risk detections for IP {self.ip}")
            return

        risk_data = [{
            "id": d.get("id"),
            "riskEventType": d.get("riskEventType"),
            "riskLevel": d.get("riskLevel"),
            "userPrincipalName": d.get("userPrincipalName"),
            "detectedDateTime": d.get("detectedDateTime"),
            "ipAddress": d.get("ipAddress"),
            "source": d.get("source"),
            "activity": d.get("activity"),
        } for d in detections]

        self.exporter.export(f"RiskDetections_{self.ip}", risk_data, self.ip_folder, investigate=True)
        log.investigate(f"Found {len(risk_data)} risk detection(s) from IP {self.ip}")


# ============================================================================
# IOC EXTRACTION ENGINE
# ============================================================================

class IOCExtractor:
    """Automatically extract Indicators of Compromise from investigation data."""

    def __init__(self, exporter: DataExporter):
        self.exporter = exporter
        self.iocs: dict[str, set] = {
            "ip_addresses": set(),
            "email_addresses": set(),
            "domains": set(),
            "user_agents": set(),
            "app_ids": set(),
            "correlation_ids": set(),
        }

    def extract_from_sign_ins(self, sign_ins: list[dict]):
        for si in sign_ins:
            ip = si.get("ipAddress")
            if ip:
                self.iocs["ip_addresses"].add(ip)
            upn = si.get("userPrincipalName", "")
            if upn:
                self.iocs["email_addresses"].add(upn)
                domain = upn.split("@")[-1] if "@" in upn else ""
                if domain:
                    self.iocs["domains"].add(domain)
            browser = (si.get("deviceDetail", {}) or {}).get("browser", "")
            if browser:
                self.iocs["user_agents"].add(browser)
            cid = si.get("correlationId")
            if cid:
                self.iocs["correlation_ids"].add(cid)

    def extract_from_alerts(self, alerts: list[dict]):
        for a in alerts:
            evidence = a.get("evidence", [])
            if isinstance(evidence, list):
                for ev in evidence:
                    if isinstance(ev, dict):
                        ip = ev.get("ipAddress")
                        if ip:
                            self.iocs["ip_addresses"].add(ip)
                        upn = ev.get("userPrincipalName", "") or ev.get("userAccount", {}).get("userPrincipalName", "")
                        if upn:
                            self.iocs["email_addresses"].add(upn)

    def extract_from_rules(self, rules: list[dict]):
        for r in rules:
            actions = r.get("actions", {}) if isinstance(r.get("actions"), dict) else {}
            for key in ["forwardTo", "forwardAsAttachmentTo", "redirectTo"]:
                for dest in (actions.get(key) or []):
                    if isinstance(dest, dict):
                        addr = dest.get("emailAddress", {}).get("address", "")
                        if addr:
                            self.iocs["email_addresses"].add(addr)
                            domain = addr.split("@")[-1] if "@" in addr else ""
                            if domain:
                                self.iocs["domains"].add(domain)

    def extract_from_apps(self, apps: list[dict]):
        for app in apps:
            app_id = app.get("appId")
            if app_id:
                self.iocs["app_ids"].add(app_id)

    def export_iocs(self):
        """Export extracted IOCs in multiple formats."""
        all_iocs = []
        for ioc_type, values in self.iocs.items():
            for val in sorted(values):
                all_iocs.append({"type": ioc_type, "value": val})

        if all_iocs:
            self.exporter.export("ExtractedIOCs", all_iocs, "IOCs")

            # Flat text IOC files for easy ingestion
            ioc_folder = os.path.join(self.exporter.output_root, "IOCs")
            os.makedirs(ioc_folder, exist_ok=True)

            for ioc_type, values in self.iocs.items():
                if values:
                    path = os.path.join(ioc_folder, f"{ioc_type}.txt")
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("\n".join(sorted(values)))

            log.success(f"Extracted {len(all_iocs)} IOCs across {sum(1 for v in self.iocs.values() if v)} categories")


# ============================================================================
# SIEM EXPORT FORMATS
# ============================================================================

class SIEMExporter:
    """Export investigation data in SIEM-compatible formats."""

    def __init__(self, output_root: str):
        self.output_root = output_root
        self.siem_folder = os.path.join(output_root, "SIEM_Export")
        os.makedirs(self.siem_folder, exist_ok=True)

    def export_splunk(self, data: list[dict], source_type: str):
        """Export in Splunk-compatible JSON format (one event per line)."""
        path = os.path.join(self.siem_folder, f"splunk_{source_type}.json")
        with open(path, "w", encoding="utf-8") as f:
            for record in data:
                event = {
                    "time": record.get("createdDateTime") or record.get("activityDateTime") or "",
                    "sourcetype": f"vcd:{source_type}",
                    "source": "vcd_cloud_investigator",
                    "event": record,
                }
                f.write(json.dumps(event, default=str) + "\n")
        log.success(f"Splunk export: {len(data)} events to splunk_{source_type}.json")

    def export_elastic(self, data: list[dict], index_name: str):
        """Export in Elasticsearch bulk format (NDJSON)."""
        path = os.path.join(self.siem_folder, f"elastic_{index_name}.ndjson")
        with open(path, "w", encoding="utf-8") as f:
            for record in data:
                action = {"index": {"_index": f"vcd-{index_name}"}}
                f.write(json.dumps(action) + "\n")
                record["@timestamp"] = record.get("createdDateTime") or record.get("activityDateTime") or ""
                record["vcd_source"] = index_name
                f.write(json.dumps(record, default=str) + "\n")
        log.success(f"Elastic export: {len(data)} events to elastic_{index_name}.ndjson")

    def export_sentinel(self, data: list[dict], table_name: str):
        """Export in Microsoft Sentinel custom log format (JSON array)."""
        path = os.path.join(self.siem_folder, f"sentinel_{table_name}.json")
        enriched = []
        for record in data:
            r = dict(record)
            r["TimeGenerated"] = r.get("createdDateTime") or r.get("activityDateTime") or ""
            r["VCD_Source"] = table_name
            r["VCD_InvestigationTool"] = f"VCD Cloud Investigator v{VERSION}"
            enriched.append(r)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(enriched, f, indent=2, default=str)
        log.success(f"Sentinel export: {len(data)} events to sentinel_{table_name}.json")


# ============================================================================
# HTML REPORT GENERATOR
# ============================================================================

class HTMLReportGenerator:
    """Generate an interactive HTML investigation report."""

    def __init__(self, output_root: str, investigation_id: str):
        self.output_root = output_root
        self.investigation_id = investigation_id

    def generate(self, inv_type: str, days: int, start_date: datetime,
                 end_date: datetime, start_time: datetime,
                 users: list[str] | None, ips: list[str] | None):
        end_time = datetime.now()
        duration = end_time - start_time

        # Count output files
        investigate_files = []
        all_files = []
        for root, _dirs, files in os.walk(self.output_root):
            for f in files:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, self.output_root)
                size_kb = os.path.getsize(full_path) / 1024
                all_files.append((rel_path, size_kb))
                if f.startswith("_Investigate_") and f.endswith(".csv"):
                    try:
                        with open(full_path, encoding="utf-8") as fh:
                            row_count = sum(1 for _ in fh) - 1
                    except OSError:
                        row_count = 0
                    investigate_files.append((rel_path, max(row_count, 0)))

        # MITRE ATT&CK summary
        mitre_rows = ""
        for mid, msgs in sorted(log.mitre_hits.items()):
            info = MITRE_ATTACK.get(mid, {})
            mitre_rows += f"""<tr>
                <td><code>{html.escape(mid)}</code></td>
                <td>{html.escape(info.get('name', 'Unknown'))}</td>
                <td>{html.escape(info.get('tactic', 'Unknown'))}</td>
                <td>{len(msgs)}</td>
            </tr>"""

        # Findings table
        findings_rows = ""
        for f in log.findings:
            sev_class = ""
            msg = f.get("message", "")
            if "[CRITICAL]" in msg:
                sev_class = "critical"
            elif "[HIGH]" in msg:
                sev_class = "high"
            elif "[MEDIUM]" in msg:
                sev_class = "medium"
            findings_rows += f"""<tr class="{sev_class}">
                <td>{html.escape(f.get('timestamp', ''))}</td>
                <td>{html.escape(msg)}</td>
                <td>{html.escape(', '.join(f.get('mitre', [])))}</td>
            </tr>"""

        # Files requiring review
        investigate_rows = ""
        for path, count in investigate_files:
            investigate_rows += f"<tr><td>{html.escape(path)}</td><td>{count}</td></tr>"

        report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VCD Cloud Investigation Report - {html.escape(self.investigation_id)}</title>
<style>
    :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
             --accent: #58a6ff; --red: #f85149; --orange: #d29922; --green: #3fb950; --purple: #bc8cff; }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
            background: var(--bg); color: var(--text); padding: 20px; }}
    .header {{ background: linear-gradient(135deg, #1a1e2e, #2d1b3d); padding: 30px;
               border-radius: 12px; margin-bottom: 20px; border: 1px solid var(--border); }}
    .header h1 {{ color: var(--accent); font-size: 24px; margin-bottom: 10px; }}
    .header .subtitle {{ color: var(--purple); font-size: 14px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
              gap: 15px; margin-bottom: 20px; }}
    .stat {{ background: var(--card); padding: 20px; border-radius: 8px;
             border: 1px solid var(--border); text-align: center; }}
    .stat .value {{ font-size: 32px; font-weight: bold; }}
    .stat .label {{ font-size: 12px; color: #8b949e; margin-top: 5px; }}
    .stat.critical .value {{ color: var(--red); }}
    .stat.warn .value {{ color: var(--orange); }}
    .stat.ok .value {{ color: var(--green); }}
    .stat.info .value {{ color: var(--accent); }}
    .section {{ background: var(--card); border-radius: 8px; padding: 20px;
                margin-bottom: 20px; border: 1px solid var(--border); }}
    .section h2 {{ color: var(--accent); margin-bottom: 15px; font-size: 18px;
                   border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ background: #21262d; color: var(--accent); padding: 8px 12px; text-align: left; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); word-break: break-word; }}
    tr:hover {{ background: #1c2128; }}
    tr.critical {{ background: rgba(248, 81, 73, 0.1); }}
    tr.high {{ background: rgba(210, 153, 34, 0.1); }}
    tr.medium {{ background: rgba(88, 166, 255, 0.05); }}
    .meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
    .meta-item {{ padding: 5px 0; }}
    .meta-label {{ color: #8b949e; font-size: 12px; }}
    .meta-value {{ color: var(--text); font-size: 14px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
    .badge-critical {{ background: var(--red); color: white; }}
    .badge-high {{ background: var(--orange); color: black; }}
    .badge-medium {{ background: var(--accent); color: black; }}
    .footer {{ text-align: center; color: #8b949e; font-size: 12px; padding: 20px; }}
    details {{ margin: 5px 0; }}
    summary {{ cursor: pointer; padding: 5px; border-radius: 4px; }}
    summary:hover {{ background: #21262d; }}
</style>
</head>
<body>
<div class="header">
    <h1>Vendetta Cyber Defense - Cloud Investigation Report</h1>
    <div class="subtitle">Investigation ID: {html.escape(self.investigation_id)} |
        Generated: {end_time.strftime('%Y-%m-%d %H:%M:%S')} |
        VCD Cloud Investigator v{VERSION}</div>
</div>

<div class="stats">
    <div class="stat critical">
        <div class="value">{log.suspicious_count}</div>
        <div class="label">Suspicious Findings</div>
    </div>
    <div class="stat warn">
        <div class="value">{len(log.mitre_hits)}</div>
        <div class="label">MITRE Techniques</div>
    </div>
    <div class="stat info">
        <div class="value">{len(all_files)}</div>
        <div class="label">Output Files</div>
    </div>
    <div class="stat ok">
        <div class="value">{str(duration).split('.')[0]}</div>
        <div class="label">Duration</div>
    </div>
</div>

<div class="section">
    <h2>Investigation Metadata</h2>
    <div class="meta">
        <div class="meta-item"><div class="meta-label">Type</div><div class="meta-value">{html.escape(inv_type)}</div></div>
        <div class="meta-item"><div class="meta-label">Lookback</div><div class="meta-value">{days} days ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})</div></div>
        <div class="meta-item"><div class="meta-label">Users</div><div class="meta-value">{html.escape(', '.join(users) if users else 'N/A')}</div></div>
        <div class="meta-item"><div class="meta-label">IPs</div><div class="meta-value">{html.escape(', '.join(ips) if ips else 'N/A')}</div></div>
    </div>
</div>

<div class="section">
    <h2>MITRE ATT&CK Coverage ({len(log.mitre_hits)} techniques)</h2>
    <table>
        <tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Hits</th></tr>
        {mitre_rows if mitre_rows else '<tr><td colspan="4">No MITRE ATT&CK techniques detected</td></tr>'}
    </table>
</div>

<div class="section">
    <h2>All Findings ({log.suspicious_count})</h2>
    <table>
        <tr><th>Timestamp</th><th>Finding</th><th>MITRE</th></tr>
        {findings_rows if findings_rows else '<tr><td colspan="3">No suspicious findings</td></tr>'}
    </table>
</div>

<div class="section">
    <h2>Files Requiring Review ({len(investigate_files)})</h2>
    <table>
        <tr><th>File</th><th>Records</th></tr>
        {investigate_rows if investigate_rows else '<tr><td colspan="2">No files flagged for review</td></tr>'}
    </table>
</div>

<div class="footer">
    VCD Cloud Investigation Tool v{VERSION} | Vendetta Cyber Defense<br>
    Advanced Cloud Forensics for Microsoft 365 / Entra ID / Azure
</div>
</body>
</html>"""

        report_dir = os.path.join(self.output_root, "Summary")
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, "InvestigationReport.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_html)

        log.success(f"HTML report generated: {report_path}")


# ============================================================================
# SUMMARY REPORT
# ============================================================================

def generate_summary(output_root: str, investigation_id: str, inv_type: str,
                     days: int, start_date: datetime, end_date: datetime,
                     start_time: datetime, exporter: DataExporter,
                     users: list[str] | None, ips: list[str] | None):
    """Generate a human-readable investigation summary report."""
    end_time = datetime.now()
    duration = end_time - start_time

    lines = [
        "=" * 80,
        "  VENDETTA CYBER DEFENSE - Cloud Investigation Summary Report",
        f"  Investigation ID: {investigation_id}",
        "=" * 80,
        "",
        f"  Investigation Type : {inv_type}",
        f"  Start Time         : {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  End Time           : {end_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Duration           : {str(duration).split('.')[0]}",
        f"  Lookback Period    : {days} days ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})",
        "",
        f"  Output Location    : {output_root}",
        f"  Total Records      : {exporter.total_records}",
        f"  Suspicious Findings: {log.suspicious_count}",
        "",
        f"  Users Investigated : {', '.join(users) if users else 'N/A'}",
        f"  IPs Investigated   : {', '.join(ips) if ips else 'N/A'}",
        "",
        "=" * 80,
        "  FILES REQUIRING REVIEW (prefixed with _Investigate_)",
        "=" * 80,
        "",
    ]

    investigate_files = []
    for root, _dirs, files in os.walk(output_root):
        for f in files:
            if f.startswith("_Investigate_") and f.endswith(".csv"):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, output_root)
                try:
                    with open(full_path, encoding="utf-8") as fh:
                        row_count = sum(1 for _ in fh) - 1  # minus header
                except OSError:
                    row_count = 0
                investigate_files.append((rel_path, max(row_count, 0)))

    if investigate_files:
        for path, count in investigate_files:
            lines.append(f"  [!] {path} ({count} records)")
    else:
        lines.append("  No suspicious findings flagged.")

    lines += [
        "",
        "=" * 80,
        "  ALL OUTPUT FILES",
        "=" * 80,
        "",
    ]

    for root, _dirs, files in os.walk(output_root):
        for f in sorted(files):
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, output_root)
            size_kb = os.path.getsize(full_path) / 1024
            lines.append(f"  {rel_path} ({size_kb:.1f} KB)")

    lines += [
        "",
        "=" * 80,
        f"  Tool: VCD Cloud Investigation Tool v{VERSION}",
        "  Based on: HAWK Cloud Forensics Framework",
        "  Author: Vendetta Cyber Defense",
        "=" * 80,
    ]

    summary_text = "\n".join(lines)

    summary_dir = os.path.join(output_root, "Summary")
    os.makedirs(summary_dir, exist_ok=True)
    summary_path = os.path.join(summary_dir, "InvestigationSummary.txt")

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_text)

    print(f"\033[36m{summary_text}\033[0m")
    log.success(f"Summary report saved to {summary_path}")


# ============================================================================
# MAIN
# ============================================================================

def get_auth_config(non_interactive: bool = False) -> dict:
    """Get authentication configuration from environment or interactive prompt."""
    tenant_id = os.environ.get("VCD_TENANT_ID") or os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("VCD_CLIENT_ID") or os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("VCD_CLIENT_SECRET") or os.environ.get("AZURE_CLIENT_SECRET")

    if not tenant_id and not non_interactive:
        print("\n  Azure AD Authentication Configuration")
        print("  (Set VCD_TENANT_ID, VCD_CLIENT_ID, VCD_CLIENT_SECRET env vars to skip)\n")
        tenant_id = input("  Tenant ID: ").strip()

    if not client_id and not non_interactive:
        client_id = input("  Client (App) ID: ").strip()

    if not client_secret and not non_interactive:
        use_secret = input("  Use client secret? (Y/N, N for interactive/device code): ").strip().lower()
        if use_secret == "y":
            client_secret = input("  Client Secret: ").strip()

    if not tenant_id or not client_id:
        log.error("Tenant ID and Client ID are required. Set VCD_TENANT_ID and VCD_CLIENT_ID env vars.")
        sys.exit(1)

    return {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
    }


def load_config(config_path: str) -> dict:
    """Load investigation config from YAML or JSON file."""
    if not os.path.exists(config_path):
        log.error(f"Config file not found: {config_path}")
        return {}

    with open(config_path, "r", encoding="utf-8") as f:
        if config_path.endswith((".yml", ".yaml")):
            if not yaml:
                log.error("PyYAML not installed. Run: pip install pyyaml")
                return {}
            return yaml.safe_load(f) or {}
        else:
            return json.load(f)


def interactive_menu() -> dict:
    """Interactive menu for selecting investigation type and parameters."""
    print("\n  Select investigation type:")
    print("  [1] Tenant     - Organization-wide security config and audit log collection")
    print("  [2] User       - Deep-dive investigation of specific user account(s)")
    print("  [3] IP         - Search all tenant activity from specific IP address(es)")
    print("  [4] Full       - Tenant + User investigation(s)")
    print("  [5] BEC        - Business Email Compromise focused investigation")
    print("  [6] Complete   - Everything: Tenant + Users + BEC + SharePoint + Teams")
    print()

    selection = input("  Enter selection (1-6): ").strip()
    type_map = {"1": "tenant", "2": "user", "3": "ip", "4": "full", "5": "bec", "6": "complete"}
    inv_type = type_map.get(selection)

    if not inv_type:
        print("  Invalid selection.")
        sys.exit(1)

    users = None
    ips = None

    if inv_type in ("user", "full", "bec", "complete"):
        upn_input = input("  Enter user principal name(s) (comma-separated): ").strip()
        users = [u.strip() for u in upn_input.split(",") if u.strip()]

    if inv_type == "ip":
        ip_input = input("  Enter IP address(es) (comma-separated): ").strip()
        ips = [i.strip() for i in ip_input.split(",") if i.strip()]

    days_input = input("  Days to look back (default 90): ").strip()
    days = int(days_input) if days_input else 90

    return {"type": inv_type, "users": users, "ips": ips, "days": days}


def main():
    parser = argparse.ArgumentParser(
        description="VCD Cloud Investigation Tool v2 - Advanced forensics for M365/Entra ID/Azure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --type tenant --days 90
  %(prog)s --type user --users user@contoso.com
  %(prog)s --type ip --ips 203.0.113.50
  %(prog)s --type full --users user@contoso.com,admin@contoso.com --days 30
  %(prog)s --type bec --users cfo@contoso.com --days 14
  %(prog)s --type complete --users user@contoso.com --days 30
  %(prog)s --config investigation.yml

Environment Variables:
  VCD_TENANT_ID        Azure AD Tenant ID
  VCD_CLIENT_ID        Azure AD App Client ID
  VCD_CLIENT_SECRET    Azure AD App Client Secret (omit for interactive/device code auth)
  VCD_CERTIFICATE_PATH Path to certificate file for cert-based auth
  VCD_CERT_PASSWORD    Certificate password (optional)

Investigation Types:
  tenant    - Organization-wide security config and audit log collection
  user      - Deep-dive investigation of specific user account(s)
  ip        - Search all tenant activity from specific IP address(es)
  full      - Tenant investigation + User investigation(s)
  bec       - Business Email Compromise focused investigation
  complete  - Everything: Tenant + Users + BEC + SharePoint + Teams + Threat Detection
        """,
    )
    parser.add_argument("--type", choices=["tenant", "user", "ip", "full", "bec", "complete"],
                        help="Investigation type")
    parser.add_argument("--users", help="Comma-separated UPN(s) for user investigation")
    parser.add_argument("--ips", help="Comma-separated IP(s) for IP investigation")
    parser.add_argument("--days", type=int, default=90, help="Days to look back (default: 90, max: 365)")
    parser.add_argument("--output", help="Output directory path")
    parser.add_argument("--config", help="Path to YAML/JSON config file")
    parser.add_argument("--non-interactive", action="store_true", help="Run without interactive prompts")
    parser.add_argument("--interactive-auth", action="store_true",
                        help="Use interactive browser auth instead of device code")
    parser.add_argument("--cert-auth", help="Path to certificate for cert-based auth")
    parser.add_argument("--cert-password", help="Certificate password")
    parser.add_argument("--workers", type=int, default=4, help="Max concurrent API workers (default: 4)")
    parser.add_argument("--no-html-report", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--siem-export", choices=["splunk", "elastic", "sentinel", "all"],
                        help="Export in SIEM format (splunk, elastic, sentinel, or all)")
    parser.add_argument("--skip-sharepoint", action="store_true", help="Skip SharePoint/OneDrive investigation")
    parser.add_argument("--skip-teams", action="store_true", help="Skip Teams investigation")
    parser.add_argument("--skip-threat-detection", action="store_true", help="Skip automated threat detection")
    parser.add_argument("--version", action="version", version=f"VCD Cloud Investigator v{VERSION}")

    args = parser.parse_args()

    # Banner
    print(BANNER.format(version=VERSION))

    # Check dependencies
    if not msal:
        print("ERROR: 'msal' package not installed. Run: pip install msal")
        sys.exit(1)
    if not requests:
        print("ERROR: 'requests' package not installed. Run: pip install requests")
        sys.exit(1)

    # Load config file if provided
    config = {}
    if args.config:
        config = load_config(args.config)
        log.info(f"Loaded config from {args.config}")

    # Interactive or CLI mode
    if not args.type and not config.get("type") and not args.non_interactive:
        params = interactive_menu()
        inv_type = params["type"]
        users = params.get("users")
        ips = params.get("ips")
        days = params.get("days", 90)
    else:
        inv_type = args.type or config.get("type")
        users = ([u.strip() for u in args.users.split(",")] if args.users
                 else config.get("users"))
        ips = ([i.strip() for i in args.ips.split(",")] if args.ips
               else config.get("ips"))
        days = args.days if args.days != 90 else config.get("days", 90)

    if not inv_type:
        parser.print_help()
        sys.exit(1)

    if inv_type in ("user", "full", "bec", "complete") and not users:
        log.error("--users is required for user/full/bec/complete investigation type")
        sys.exit(1)
    if inv_type == "ip" and not ips:
        log.error("--ips is required for IP investigation type")
        sys.exit(1)

    days = max(1, min(365, days))

    # Timestamps
    start_time = datetime.now()
    investigation_id = str(uuid.uuid4())[:8]
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    end_date = datetime.now(timezone.utc)

    # Output
    output_root = args.output or config.get("output")
    if not output_root:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_root = os.path.join(os.getcwd(), f"VCDCloudInvestigation_{ts}")

    os.makedirs(output_root, exist_ok=True)
    for folder in ("Tenant", "Users", "IP_Investigation", "Summary",
                    "ThreatDetection", "IOCs", "BEC_Investigation",
                    "SharePoint", "Teams", "SIEM_Export", "Analysis",
                    "Timeline", "KQL_Queries", "Remediation"):
        os.makedirs(os.path.join(output_root, folder), exist_ok=True)

    log.set_output_root(output_root)
    exporter = DataExporter(output_root)

    # Save investigation metadata
    meta = {
        "investigationId": investigation_id,
        "version": VERSION,
        "type": inv_type,
        "days": days,
        "startDate": start_date.isoformat(),
        "endDate": end_date.isoformat(),
        "startTime": start_time.isoformat(),
        "users": users,
        "ips": ips,
        "outputRoot": output_root,
    }
    meta_path = os.path.join(output_root, "investigation_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, default=str)

    log.info(f"Investigation ID: {investigation_id}")
    log.info(f"Investigation Type: {inv_type}")
    log.info(f"Lookback: {days} days ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})")
    log.info(f"Output: {output_root}")
    log.info(f"Concurrent workers: {args.workers}")

    # Authenticate
    auth_config = get_auth_config(args.non_interactive)
    cert_path = args.cert_auth or os.environ.get("VCD_CERTIFICATE_PATH")
    cert_password = args.cert_password or os.environ.get("VCD_CERT_PASSWORD")

    graph = GraphClient(
        tenant_id=auth_config["tenant_id"],
        client_id=auth_config["client_id"],
        client_secret=auth_config.get("client_secret"),
        interactive=args.interactive_auth,
        certificate_path=cert_path,
        certificate_password=cert_password,
        max_workers=args.workers,
    )

    if not graph.authenticate():
        log.error("Authentication failed. Exiting.")
        sys.exit(1)

    # Initialize threat detection and IOC extraction
    threat_engine = ThreatDetectionEngine(exporter) if not args.skip_threat_detection else None
    ioc_extractor = IOCExtractor(exporter)

    # Data holders reused across modules
    all_sign_ins = []
    all_alerts = []

    # ── Tenant Investigation ──
    if inv_type in ("tenant", "full", "complete"):
        tenant = TenantInvestigator(graph, exporter, start_date, end_date)
        tenant.run_all()

    # ── User Investigation ──
    if inv_type in ("user", "full", "complete"):
        for upn in users:
            user_inv = UserInvestigator(graph, exporter, upn, start_date, end_date)
            user_inv.run_all()

    # ── BEC Investigation ──
    if inv_type in ("bec", "complete"):
        for upn in users:
            bec = BECInvestigator(graph, exporter, upn, start_date, end_date)
            bec.run_all()

    # ── IP Investigation ──
    if inv_type == "ip":
        for ip in ips:
            ip_inv = IPInvestigator(graph, exporter, ip, start_date, end_date)
            ip_inv.run_all()

    # ── SharePoint/OneDrive Investigation ──
    if inv_type == "complete" and not args.skip_sharepoint:
        sp = SharePointInvestigator(graph, exporter, start_date, end_date)
        sp.run_all()

    # ── Teams Investigation ──
    if inv_type == "complete" and not args.skip_teams:
        teams = TeamsInvestigator(graph, exporter)
        teams.run_all()

    # ── Threat Detection Engine ──
    if threat_engine:
        log.info("=" * 50)
        log.info("Running Automated Threat Detection Engine")
        log.info("=" * 50)

        # Collect data for analysis (reused by timeline, SIEM export, etc.)
        all_sign_ins = graph.get_all("auditLogs/signIns", max_records=5000)
        all_apps = graph.get_all("applications")
        all_grants = graph.get_all("oauth2PermissionGrants")
        all_sps = graph.get_all("servicePrincipals")
        all_alerts = graph.get_all("security/alerts_v2", beta=True)
        domains = graph.get_all("domains")
        ca_policies = graph.get_all("identity/conditionalAccess/policies")

        threat_engine.analyze_sign_ins(all_sign_ins)
        threat_engine.analyze_app_permissions(all_grants, all_apps)
        threat_engine.analyze_service_principals(all_sps)
        threat_engine.analyze_federation(domains)
        threat_engine.analyze_conditional_access(ca_policies)

        # Per-user inbox rule analysis
        if users:
            for upn in users:
                rules_raw = graph.get_all(f"users/{upn}/mailFolders/inbox/messageRules")
                if rules_raw:
                    threat_engine.analyze_inbox_rules(rules_raw, upn=upn)

        threat_engine.export_results()

        # IOC extraction from collected data
        ioc_extractor.extract_from_sign_ins(all_sign_ins)
        ioc_extractor.extract_from_apps(all_apps)
        ioc_extractor.extract_from_alerts(all_alerts)

        # Remediation recommendations
        remediation = RemediationEngine(exporter, threat_engine.detections)
        remediation.generate()

    # ── Advanced Sign-In Analysis ──
    if inv_type in ("full", "complete"):
        log.info("=" * 50)
        log.info("Running Advanced Sign-In Analysis")
        log.info("=" * 50)

        if not threat_engine:
            all_sign_ins = graph.get_all("auditLogs/signIns", max_records=5000)
        analyzer = SignInAnalyzer(exporter)
        analyzer.analyze_user_agents(all_sign_ins)
        analyzer.analyze_countries(all_sign_ins)
        analyzer.analyze_sessions(all_sign_ins)
        analyzer.analyze_app_usage(all_sign_ins)

    # ── Unified Timeline ──
    if inv_type in ("full", "complete"):
        log.info("=" * 50)
        log.info("Generating Unified Investigation Timeline")
        log.info("=" * 50)

        timeline = TimelineGenerator(exporter)
        if not threat_engine:
            all_sign_ins = graph.get_all("auditLogs/signIns", max_records=5000)
        timeline.add_sign_ins(all_sign_ins)

        audit_logs = graph.get_all("auditLogs/directoryAudits", max_records=5000)
        timeline.add_audit_logs(audit_logs)

        all_alerts = graph.get_all("security/alerts_v2", beta=True) if not threat_engine else all_alerts
        timeline.add_alerts(all_alerts)

        risk_dets = graph.get_all("identityProtection/riskDetections", max_records=2000)
        timeline.add_risk_detections(risk_dets)

        timeline.generate()

    # ── IOC Export ──
    ioc_extractor.export_iocs()

    # ── STIX IOC Export ──
    stix = STIXExporter(output_root, investigation_id)
    stix.export(ioc_extractor.iocs)

    # ── KQL Query Generation ──
    log.info("Generating Sentinel KQL hunting queries")
    kql = KQLQueryGenerator(output_root)
    kql.generate_all_default()
    if ips:
        for ip in ips:
            kql.add_ip_query(ip)
    if users:
        for upn in users:
            kql.add_user_query(upn)
    kql.export()

    # ── SIEM Export ──
    if args.siem_export:
        log.info(f"Exporting data in SIEM format: {args.siem_export}")
        siem = SIEMExporter(output_root)

        # Reuse already collected data or fetch fresh
        if 'all_sign_ins' not in dir():
            all_sign_ins = graph.get_all("auditLogs/signIns", max_records=5000)
        if 'all_alerts' not in dir():
            all_alerts = graph.get_all("security/alerts_v2", beta=True)

        if args.siem_export in ("splunk", "all"):
            if all_sign_ins:
                siem.export_splunk(all_sign_ins, "sign_ins")
            if all_alerts:
                siem.export_splunk(all_alerts, "security_alerts")
            if threat_engine and threat_engine.detections:
                siem.export_splunk(threat_engine.detections, "threat_detections")

        if args.siem_export in ("elastic", "all"):
            if all_sign_ins:
                siem.export_elastic(all_sign_ins, "sign-ins")
            if all_alerts:
                siem.export_elastic(all_alerts, "security-alerts")

        if args.siem_export in ("sentinel", "all"):
            if all_sign_ins:
                siem.export_sentinel(all_sign_ins, "VCD_SignIns")
            if all_alerts:
                siem.export_sentinel(all_alerts, "VCD_SecurityAlerts")

    # ── Summary Report ──
    generate_summary(output_root, investigation_id, inv_type, days,
                     start_date, end_date, start_time, exporter, users, ips)

    # ── HTML Report ──
    if not args.no_html_report:
        html_gen = HTMLReportGenerator(output_root, investigation_id)
        html_gen.generate(inv_type, days, start_date, end_date, start_time, users, ips)

    # ── Final Stats ──
    log.success("=" * 60)
    log.success(f"Investigation complete. ID: {investigation_id}")
    log.success(f"Output: {output_root}")
    log.success(f"Total records collected: {exporter.total_records}")
    log.success(f"Suspicious findings: {log.suspicious_count}")
    log.success(f"MITRE techniques matched: {len(log.mitre_hits)}")
    log.success(f"API calls made: {graph.api_call_count}")
    if threat_engine:
        critical = sum(1 for d in threat_engine.detections if d["severity"] == "CRITICAL")
        high = sum(1 for d in threat_engine.detections if d["severity"] == "HIGH")
        log.success(f"Threat detections: {len(threat_engine.detections)} "
                     f"({critical} critical, {high} high)")
    log.success("=" * 60)


if __name__ == "__main__":
    main()
