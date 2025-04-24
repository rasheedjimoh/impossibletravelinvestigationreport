# 🛰️ Impossible Travel Investigation Report

[![Security](https://img.shields.io/badge/Incident-Response-critical?style=flat&logo=datadog&color=red)](https://learn.microsoft.com/en-us/azure/sentinel/)
[![Azure Sentinel](https://img.shields.io/badge/Azure-Sentinel-blue?style=flat&logo=microsoftazure)](https://azure.microsoft.com/en-us/products/microsoft-sentinel/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blueviolet?style=flat&logo=mitre)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/Status-Resolved-brightgreen?style=flat&logo=checkmarx)]()

---

## 📅 Timeline ⏳

```text
🕵️‍♂️ Initial Detection  →  Multiple sign-ins from geographically distant locations
🔎 Analysis Begins       →  12 user accounts flagged for review
📍 Logon Investigation   →  Anomalous locations spotted within a tight timeframe
🚨 True Positive Alert   →  One account highly suspicious (Ashburn VA ↔ Georgia logins)
🚫 Containment Actions   →  Account disabled, password reset enforced
🧪 Post-Mortem Analysis  →  Geo-fencing discussed, incident documented
```

---

## 🔍 Detection and Analysis

> **Goal:** Detect and validate cases of "impossible travel" — where a user logs in from two or more distant geographic locations within a time window that would be physically impossible to traverse.

### 🚩 Flagged Accounts
Some of the 12 flagged accounts:

- `cdf38e188df8889ea023840f8f26bb0b4fa6c0f87cd9764b56cd80cfa2ed2e78@lognpacific.com`  
  `UserId: 61695a2a-5387-414d-8d59-6e0b6063f0e3`

- `540b56f136651e0a8e5d548928eba7596b5eb50ce18e4d513bfaf572ef2f7a92@lognpacific.com`  
  `UserId: 2358438e-d7af-4ab2-99b1-cb2d90997251`

---

### 📊 KQL Query: Detect Impossible Travel

```kql
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d); 
let NumberOfDifferentLocationsAllowed = 2;

SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by 
    UserPrincipalName, 
    UserId, 
    City = tostring(parse_json(LocationDetails).city), 
    State = tostring(parse_json(LocationDetails).state), 
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

---

## 🧭 Account-Level Investigation

### 🎯 User Location Timeline Query

```kql
let TimePeriodThreshold = timespan(7d);

SigninLogs
| where UserPrincipalName == "b7274fe8d9adaef8f9fae7e19e1fb62c280679d3c52ecfc2a8edc59ca5560b6b@lognpacific.com"
      and TimeGenerated > ago(TimePeriodThreshold)
| project 
    TimeGenerated, 
    UserPrincipalName, 
    City = tostring(parse_json(LocationDetails).city), 
    State = tostring(parse_json(LocationDetails).state), 
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc 
```

### 🧠 Findings

- One user accessed services from **four different cities** within a 7-day period.
- Notably, the user logged in from **Ashburn, VA**, just **three hours after** being logged in from **Georgia**, raising impossible travel suspicion.
- This indicates the high likelihood of **credential theft** or **session hijacking**.

---

## 🚑 Containment, Eradication & Recovery

The event was confirmed as a **TRUE POSITIVE**.

### 🔒 Actions Taken:

- 🚫 **Account disabled** to prevent further misuse.
- 📞 **User contacted by management** — confirmed they were **not traveling**.
- 🔍 No suspicious Azure or M365 activity was found.
- 🔁 **Forced password reset** performed immediately.

### 🧾 Audit Query for Activity Review

```kql
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "2358438e-d7af-4ab2-99b1-cb2d90997251"
```

---

## 🧠 Post-Incident Activities

- 🧱 **Explored Geo-Fencing Options**: Enforce login restrictions based on known geographies.
- ⚙️ **Recommendations**:
  - Deploy **Conditional Access** with location-based policies.
  - Enforce **MFA for high-risk logins**.
  - Monitor **impossible travel** patterns automatically with detection rules.

---

## ✅ Conclusion

> Through swift detection, investigation, and response, this potential account compromise was contained with minimal impact. This case supports the need for automated geo-anomaly detection and responsive identity controls.

---
