# Lab Environment

## 1. Overview

This lab implements a small SOC detection and response environment using LimaCharlie as the EDR platform and Tines as the SOAR platform. The environment monitors multiple Windows endpoints, generates detections from custom rules, sends alerts to analysts, and supports analyst-approved endpoint isolation.

## 2. Environment Components

| Component | Role |
|---|---|
| Windows analyst workstation | Used to manage LimaCharlie, Tines, Slack, email, and incident-response actions |
| Windows Server 2019 VM | Monitored endpoint used for LaZagne detection validation |
| Windows 10 VM | Monitored endpoint used for LaZagne testing and planned Suspicious PowerShell validation |
| LimaCharlie | Endpoint telemetry collection, custom D&R rules, detections, remote tasking, and network isolation |
| Tines | Webhook ingestion, alert enrichment, notifications, analyst approval, and response automation |
| Slack | Real-time SOC alerting and response-status notifications |
| Email | Secondary alert-delivery channel |
| VMware | Virtualization platform hosting the monitored Windows endpoints |

## 3. Endpoint Monitoring

LimaCharlie sensors are installed on the monitored Windows endpoints using an installation key generated from the LimaCharlie organization.

The repository's current Suspicious PowerShell rule still references the legacy sensor tag `win11-home`. Before validation on Windows 10, verify or adjust the rule's scope. The two use cases in scope are LaZagne and Suspicious PowerShell.

## 4. High-Level Data Flow

```text
Windows Endpoint
      |
      | LimaCharlie sensor telemetry
      v
LimaCharlie D&R Rules
      |
      | Detection webhook
      v
Tines SOAR Workflow
      |
      +--> Slack Alert
      |
      +--> Email Alert
      |
      +--> Analyst User Prompt
                |
                +--> YES: Call LimaCharlie isolation API
                |
                +--> NO: Keep endpoint connected
```

## 5. Network and Access Model

All systems are deployed in a controlled lab environment. The monitored endpoints are not joined to an Active Directory domain and currently operate with equivalent endpoint roles.

The analyst workstation is used to:

- Access LimaCharlie and review endpoint telemetry.
- Access the Tines Story and review events.
- Approve or reject endpoint isolation.
- Execute remote investigation and containment actions through LimaCharlie.

## 6. Security Considerations

The following information must never be committed to the public repository:

- LimaCharlie installation keys
- API keys and authorization headers
- Tines webhook URLs
- Slack credentials or webhook URLs
- Email addresses used by the workflow
- LimaCharlie Organization IDs
- Sensor IDs
- Public IP addresses
- Unredacted detection links

All screenshots and exported workflow files must be sanitized before publication.
