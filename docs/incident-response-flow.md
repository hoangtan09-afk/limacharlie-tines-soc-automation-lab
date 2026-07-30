# Incident Response Flow

## 1. Overview

The Tines Story implements a human-in-the-loop response workflow. LimaCharlie performs endpoint monitoring and detection, while Tines handles notification, analyst approval, API-based isolation, and status reporting.

## 2. Workflow Stages

### Stage 1: Detection Generation

A monitored endpoint executes behavior matching a LimaCharlie D&R rule.

Examples include:

- `LaZagne.exe all`
- PowerShell with `-EncodedCommand`
- `schtasks.exe /Create`

LimaCharlie generates a detection containing the rule name, event details, endpoint routing information, and a detection link.

### Stage 2: Webhook Ingestion

LimaCharlie forwards the detection to the Tines webhook action:

```text
Retrieve Detections
```

The webhook event becomes the source object used by all downstream Tines actions.

### Stage 3: Alert Delivery

Tines sends the alert through two channels:

```text
Slack
Email
```

The alert includes:

- Detection title
- Timestamp
- Hostname
- Internal IP address
- Username or fallback value
- File path
- Command line
- Sensor ID
- Detection link

### Stage 4: Analyst Decision

The Tines User Prompt displays the incident context and asks whether the affected endpoint should be isolated.

```text
YES → Isolate endpoint
NO  → Leave endpoint connected
```

This design prevents automatic containment based only on a single medium-severity detection.

### Stage 5A: Approved Isolation

When the analyst selects `YES`, Tines sends an HTTP request to the LimaCharlie REST API using the affected endpoint's Sensor ID.

```text
User Prompt
    |
    v
Condition: YES
    |
    v
HTTP Request: Isolate Sensor
    |
    v
HTTP Request: Get Isolation Status
```

The workflow then checks the resulting isolation state.

Expected status values:

```text
Isolation status: true
Isolation status: false
```

### Stage 5B: Rejected Isolation

When the analyst selects `NO`, Tines does not call the isolation API. A Slack notification records that the endpoint was not isolated.

## 3. End-to-End Flow

```text
Suspicious Activity
        |
        v
LimaCharlie Sensor Telemetry
        |
        v
Custom D&R Rule
        |
        v
LimaCharlie Detection
        |
        v
Tines Webhook
   /       |       \
  v        v        v
Slack    Email   User Prompt
                    |
              +-----+-----+
              |           |
             YES          NO
              |           |
              v           v
      Isolate Sensor   Notify Slack
              |
              v
     Get Isolation Status
              |
              v
        Notify Slack
```

## 4. Response Design Rationale

The workflow uses analyst approval because:

- Process-based detections may produce false positives.
- Endpoint isolation can interrupt business operations.
- The analyst should review the command line and endpoint context.
- Human approval demonstrates a realistic SOC escalation and containment process.

## 5. Failure Handling

The following conditions should be considered during testing:

### Sensor Disconnected

If the LimaCharlie sensor is not maintaining its cloud tasking channel, isolation may remain in a transitional state such as:

```text
Awaiting Isolate
Pending Rejoin
```

### Missing Telemetry Fields

Fields such as `USER_NAME` may be absent. Tines uses fallback values rather than leaving the alert blank.

### Isolation Request Failure

If the API request succeeds but the endpoint does not confirm the new state, the workflow reports:

```text
Isolation status: false
```

The analyst should then verify:

- Sensor connectivity
- Last Time Alive
- LimaCharlie Console tasking
- Local sensor service status
- API response details

## 6. Production Improvements

Potential future improvements include:

- Severity-based routing
- Automatic enrichment with hash reputation
- Case creation and incident tracking
- Analyst identity and decision logging
- Timeout and retry logic
- Automatic rejoin approval workflow
- Detection deduplication
- Separate response playbooks by rule category
