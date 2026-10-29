# Lab 01: M365 BEC Detection & Query Language Synthesis (KQL vs. SPL)

## 1. Scenario Overview
* **Objective:** Identify unauthorized Microsoft 365 OAuth consent grants and hidden inbox auto-forwarding rules resulting from anomalous account access.
* **Attack Vector:** Business Email Compromise (BEC) followed by Defense Evasion & Persistence.
* **MITRE ATT&CK Mapping:**
  * **T1098.003:** Account Manipulation — Additional Email Delegate Permissions
  * **T1114.003:** Email Collection — Email Forwarding Rule
  * **T1204.002:** User Execution — Malicious File / Stager

---

## 2. Detection Engineering & Telemetry Comparison

### A. Microsoft 365 / Sentinel (KQL)
This query checks the Unified Audit Log (UAL) for third-party application consent grants while extracting nested JSON parameters via pipeline transformations.

```kusto
AuditLogs
| where TimeGenerated >= ago(7d)
| where OperationName == "Consent to application"
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where TargetApp !in ("Microsoft Office", "Teams", "OneDrive")
| project TimeGenerated, InitiatedBy, TargetApp, Result, AdditionalDetails
