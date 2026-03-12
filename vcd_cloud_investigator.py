#!/usr/bin/env python3
"""
Vendetta Cyber Defense - Cloud Investigation Tool
A HAWK-inspired forensic data collection tool for Microsoft 365 and Entra ID environments.

Based on: HAWK Cloud Forensics Framework (https://github.com/T0pCyber/hawk)
Author:   Vendetta Cyber Defense

Usage:
    # Interactive mode
    python vcd_cloud_investigator.py

    # Tenant investigation
    python vcd_cloud_investigator.py --type tenant --days 90

    # User investigation
    python vcd_cloud_investigator.py --type user --users user@contoso.com

    # IP investigation
    python vcd_cloud_investigator.py --type ip --ips 203.0.113.50

    # Full investigation (tenant + users)
    python vcd_cloud_investigator.py --type full --users user@contoso.com,admin@contoso.com --days 30

    # Non-interactive with custom output
    python vcd_cloud_investigator.py --type tenant --output /path/to/output --non-interactive

Requirements:
    pip install -r requirements.txt
    Requires Azure AD app registration with appropriate Microsoft Graph API permissions.
"""

import argparse
import csv
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import msal
except ImportError:
    msal = None

try:
    import requests
except ImportError:
    requests = None

# ============================================================================
# CONSTANTS
# ============================================================================

VERSION = "1.0.0"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

GRAPH_SCOPES = [
    "https://graph.microsoft.com/.default"
]

# Permissions required (application permissions for the app registration):
# AuditLog.Read.All, Directory.Read.All, User.Read.All, Application.Read.All,
# Policy.Read.All, RoleManagement.Read.All, SecurityEvents.Read.All,
# IdentityRiskEvent.Read.All, Reports.Read.All, Mail.Read,
# MailboxSettings.Read, Organization.Read.All

HIGH_PRIVILEGE_ROLES = [
    "Global Administrator",
    "Privileged Role Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
]

DANGEROUS_SCOPES = [
    "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All",
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
]

SENSITIVE_AUDIT_OPERATIONS = [
    "HardDelete", "SoftDelete", "MoveToDeletedItems", "SendAs",
    "SendOnBehalf", "UpdateInboxRules", "Set-Mailbox",
    "Add-MailboxPermission", "New-InboxRule", "Set-InboxRule",
    "Remove-InboxRule", "MailItemsAccessed",
]

INBOX_RULE_OPERATIONS = [
    "New-InboxRule", "Set-InboxRule", "Remove-InboxRule",
    "Enable-InboxRule", "Disable-InboxRule", "UpdateInboxRules",
]

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
     HAWK-Inspired Cloud Forensics for Microsoft 365 / Entra ID
    ============================================================
"""


# ============================================================================
# LOGGING
# ============================================================================

class VCDLogger:
    """Custom logger with investigation-specific levels and file + console output."""

    COLORS = {
        "INFO": "\033[37m",       # white
        "WARN": "\033[33m",       # yellow
        "ERROR": "\033[31m",      # red
        "SUCCESS": "\033[32m",    # green
        "INVESTIGATE": "\033[35m",  # magenta
        "RESET": "\033[0m",
    }

    def __init__(self, output_root: str | None = None):
        self.output_root = output_root
        self.suspicious_count = 0

    def set_output_root(self, path: str):
        self.output_root = path

    def _write(self, level: str, message: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color = self.COLORS.get(level, self.COLORS["INFO"])
        reset = self.COLORS["RESET"]
        label = "OK" if level == "SUCCESS" else ("!!! INVESTIGATE" if level == "INVESTIGATE" else level)

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

    def investigate(self, msg: str):
        self.suspicious_count += 1
        self._write("INVESTIGATE", msg)


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
    """Microsoft Graph API client using MSAL for authentication."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str | None = None,
                 interactive: bool = False):
        if not msal:
            raise ImportError("msal package is required. Install with: pip install msal")
        if not requests:
            raise ImportError("requests package is required. Install with: pip install requests")

        self.tenant_id = tenant_id
        self.client_id = client_id
        self.token = None
        self.token_expiry = None

        authority = f"https://login.microsoftonline.com/{tenant_id}"

        if client_secret:
            # App-only (client credentials) flow
            self.app = msal.ConfidentialClientApplication(
                client_id,
                authority=authority,
                client_credential=client_secret,
            )
            self._auth_mode = "client_credentials"
        elif interactive:
            # Delegated (interactive) flow
            self.app = msal.PublicClientApplication(
                client_id,
                authority=authority,
            )
            self._auth_mode = "interactive"
        else:
            # Device code flow (for headless/SSH scenarios)
            self.app = msal.PublicClientApplication(
                client_id,
                authority=authority,
            )
            self._auth_mode = "device_code"

    def authenticate(self) -> bool:
        """Acquire an access token."""
        try:
            if self._auth_mode == "client_credentials":
                result = self.app.acquire_token_for_client(scopes=GRAPH_SCOPES)
            elif self._auth_mode == "interactive":
                result = self.app.acquire_token_interactive(
                    scopes=["AuditLog.Read.All", "Directory.Read.All", "User.Read.All",
                            "Application.Read.All", "Policy.Read.All",
                            "RoleManagement.Read.All", "Reports.Read.All"],
                )
            else:
                flow = self.app.initiate_device_flow(
                    scopes=["AuditLog.Read.All", "Directory.Read.All", "User.Read.All",
                            "Application.Read.All", "Policy.Read.All",
                            "RoleManagement.Read.All", "Reports.Read.All"],
                )
                if "user_code" in flow:
                    print(f"\n  To authenticate, visit: {flow['verification_uri']}")
                    print(f"  Enter code: {flow['user_code']}\n")
                result = self.app.acquire_token_by_device_flow(flow)

            if "access_token" in result:
                self.token = result["access_token"]
                self.token_expiry = datetime.now(timezone.utc) + timedelta(
                    seconds=result.get("expires_in", 3600)
                )
                log.success(f"Authenticated to tenant {self.tenant_id}")
                return True
            else:
                error = result.get("error_description", result.get("error", "Unknown error"))
                log.error(f"Authentication failed: {error}")
                return False
        except Exception as e:
            log.error(f"Authentication failed: {e}")
            return False

    def _ensure_token(self):
        """Refresh token if expired."""
        if not self.token or (self.token_expiry and datetime.now(timezone.utc) >= self.token_expiry):
            self.authenticate()

    def _headers(self) -> dict:
        self._ensure_token()
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "ConsistencyLevel": "eventual",
        }

    def get(self, endpoint: str, params: dict | None = None,
            beta: bool = False, top: int | None = None) -> dict | None:
        """Make a GET request to Graph API."""
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = f"{base}/{endpoint.lstrip('/')}"

        if params is None:
            params = {}
        if top:
            params["$top"] = top

        try:
            resp = requests.get(url, headers=self._headers(), params=params, timeout=60)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            log.error(f"Graph API error ({endpoint}): {e} - {resp.text[:500]}")
            return None
        except Exception as e:
            log.error(f"Graph API request failed ({endpoint}): {e}")
            return None

    def get_all(self, endpoint: str, params: dict | None = None,
                beta: bool = False, max_records: int = 5000) -> list[dict]:
        """Get all pages of results from a Graph API endpoint."""
        results = []
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = f"{base}/{endpoint.lstrip('/')}"

        if params is None:
            params = {}
        params.setdefault("$top", 999)

        while url and len(results) < max_records:
            try:
                resp = requests.get(url, headers=self._headers(), params=params, timeout=60)
                resp.raise_for_status()
                data = resp.json()
                results.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                params = {}  # nextLink includes params
            except Exception as e:
                log.error(f"Graph API pagination error ({endpoint}): {e}")
                break

        return results[:max_records]


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
        log.info("Starting Tenant Investigation")
        log.info("=" * 50)

        self.get_organization_config()
        self.get_domains()
        self.get_consent_grants()
        self.get_app_registrations()
        self.get_service_principals()
        self.get_directory_roles()
        self.get_role_change_audit()
        self.get_conditional_access_policies()
        self.get_ediscovery_roles()
        self.get_inbox_rule_audit()
        self.get_transport_rule_audit()
        self.get_security_alerts()
        self.get_risky_users()

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
        log.investigate(f"Found {len(alert_data)} security alert(s)")

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
        log.investigate(f"Found {len(user_data)} risky user(s)")


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
        log.info(f"Starting User Investigation: {self.upn}")
        log.info("=" * 50)

        self.get_user_config()
        self.get_mailbox_settings()
        self.get_inbox_rules()
        self.get_sign_in_logs()
        self.get_audit_logs()
        self.get_registered_devices()
        self.get_app_role_assignments()
        self.get_oauth_grants()
        self.get_group_memberships()
        self.get_risk_detections()

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
        log.investigate(f"Found {len(risk_data)} risk detection(s) for {self.upn}")


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


def interactive_menu() -> dict:
    """Interactive menu for selecting investigation type and parameters."""
    print("\n  Select investigation type:")
    print("  [1] Tenant  - Organization-wide security config and audit log collection")
    print("  [2] User    - Deep-dive investigation of specific user account(s)")
    print("  [3] IP      - Search all tenant activity from specific IP address(es)")
    print("  [4] Full    - Tenant investigation + User investigation(s)")
    print()

    selection = input("  Enter selection (1-4): ").strip()
    type_map = {"1": "tenant", "2": "user", "3": "ip", "4": "full"}
    inv_type = type_map.get(selection)

    if not inv_type:
        print("  Invalid selection.")
        sys.exit(1)

    users = None
    ips = None

    if inv_type in ("user", "full"):
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
        description="VCD Cloud Investigation Tool - HAWK-inspired forensics for M365/Entra ID",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --type tenant --days 90
  %(prog)s --type user --users user@contoso.com
  %(prog)s --type ip --ips 203.0.113.50
  %(prog)s --type full --users user@contoso.com,admin@contoso.com --days 30

Environment Variables:
  VCD_TENANT_ID      Azure AD Tenant ID
  VCD_CLIENT_ID      Azure AD App Client ID
  VCD_CLIENT_SECRET  Azure AD App Client Secret (omit for interactive/device code auth)
        """,
    )
    parser.add_argument("--type", choices=["tenant", "user", "ip", "full"],
                        help="Investigation type")
    parser.add_argument("--users", help="Comma-separated UPN(s) for user investigation")
    parser.add_argument("--ips", help="Comma-separated IP(s) for IP investigation")
    parser.add_argument("--days", type=int, default=90, help="Days to look back (default: 90, max: 365)")
    parser.add_argument("--output", help="Output directory path")
    parser.add_argument("--non-interactive", action="store_true", help="Run without interactive prompts")
    parser.add_argument("--interactive-auth", action="store_true",
                        help="Use interactive browser auth instead of device code")
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

    # Interactive or CLI mode
    if not args.type and not args.non_interactive:
        params = interactive_menu()
        inv_type = params["type"]
        users = params.get("users")
        ips = params.get("ips")
        days = params.get("days", 90)
    else:
        inv_type = args.type
        users = [u.strip() for u in args.users.split(",")] if args.users else None
        ips = [i.strip() for i in args.ips.split(",")] if args.ips else None
        days = args.days

    if not inv_type:
        parser.print_help()
        sys.exit(1)

    if inv_type in ("user", "full") and not users:
        log.error("--users is required for user/full investigation type")
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
    if args.output:
        output_root = args.output
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_root = os.path.join(os.getcwd(), f"VCDCloudInvestigation_{ts}")

    os.makedirs(output_root, exist_ok=True)
    for folder in ("Tenant", "Users", "IP_Investigation", "Summary"):
        os.makedirs(os.path.join(output_root, folder), exist_ok=True)

    log.set_output_root(output_root)
    exporter = DataExporter(output_root)

    log.info(f"Investigation ID: {investigation_id}")
    log.info(f"Investigation Type: {inv_type}")
    log.info(f"Lookback: {days} days ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})")
    log.info(f"Output: {output_root}")

    # Authenticate
    auth_config = get_auth_config(args.non_interactive)
    graph = GraphClient(
        tenant_id=auth_config["tenant_id"],
        client_id=auth_config["client_id"],
        client_secret=auth_config.get("client_secret"),
        interactive=args.interactive_auth,
    )

    if not graph.authenticate():
        log.error("Authentication failed. Exiting.")
        sys.exit(1)

    # Execute investigation
    if inv_type in ("tenant", "full"):
        tenant = TenantInvestigator(graph, exporter, start_date, end_date)
        tenant.run_all()

    if inv_type in ("user", "full"):
        for upn in users:
            user_inv = UserInvestigator(graph, exporter, upn, start_date, end_date)
            user_inv.run_all()

    if inv_type == "ip":
        for ip in ips:
            ip_inv = IPInvestigator(graph, exporter, ip, start_date, end_date)
            ip_inv.run_all()

    # Summary
    generate_summary(output_root, investigation_id, inv_type, days,
                     start_date, end_date, start_time, exporter, users, ips)

    log.success("=" * 50)
    log.success(f"Investigation complete. Output: {output_root}")
    log.success("=" * 50)


if __name__ == "__main__":
    main()
