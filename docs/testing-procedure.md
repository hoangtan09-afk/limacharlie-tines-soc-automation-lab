# Testing Procedure

## 1. Purpose

This document describes the controlled tests used to validate the complete detection and response pipeline:

```text
Endpoint Activity
→ LimaCharlie Detection
→ Tines Webhook
→ Slack and Email
→ Analyst Prompt
→ Optional Isolation
```

All tests must be performed only in an authorized lab environment.

## 2. Pre-Test Checklist

Before each test, verify:

- The target VM is powered on.
- The LimaCharlie sensor shows `Receiving`.
- The sensor's `Last Time Alive` is current.
- The Windows 11 Home sensor has the `win11-home` tag.
- The relevant D&R rule is enabled.
- The Tines Story is enabled.
- Slack and email actions are connected.
- The endpoint is not already isolated.
- Sensitive values are not visible in screenshots.

---

## 3. Test Case 1: LaZagne Detection

### Target

```text
Windows Server VM
```

### Command

Run the approved lab copy of LaZagne:

```powershell
.\LaZagne.exe all
```

### Expected Result

1. LimaCharlie records a process event.
2. The LaZagne D&R rule matches.
3. A detection named `Eric - HackTool - Lazagne (SOAR-EDR)` is generated.
4. Tines receives the webhook event.
5. Slack and email alerts are delivered.
6. The User Prompt displays the affected endpoint.
7. Selecting `YES` initiates endpoint isolation.
8. Slack reports the resulting isolation status.

### Cleanup

Remove the lab tool from the endpoint after testing and restore the endpoint network state if it was isolated.

---

## 4. Test Case 2: Suspicious Encoded PowerShell

### Target

```text
Windows 11 Home VM
```

### Safe Test Command

```powershell
$payload = 'Write-Output "LIMACHARLIE-POWERSHELL-TEST"'

$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($payload)
)

powershell.exe -NoProfile -EncodedCommand $encoded
```

### Expected Result

The command should print:

```text
LIMACHARLIE-POWERSHELL-TEST
```

The detection pipeline should generate:

```text
Eric - Suspicious PowerShell Execution
```

The Slack, email, and User Prompt outputs should show the PowerShell file path and encoded command line.

### Cleanup

No persistent changes are created by this test.

---

## 5. Test Case 3: Scheduled Task Creation

### Target

```text
Windows 11 Home VM
```

### Safe Test Command

Run PowerShell or Command Prompt as Administrator:

```powershell
schtasks.exe /Create /TN "SOC-LAB-PERSISTENCE" /SC ONLOGON /TR "notepad.exe" /F
```

This creates a scheduled task that opens Notepad when a user logs on.

### Expected Result

The detection pipeline should generate:

```text
Eric - Suspicious Scheduled Task Creation
```

The alert should contain:

```text
File Path: C:\Windows\System32\schtasks.exe
Command Line: schtasks.exe /Create ...
```

### Cleanup

Delete the test task:

```powershell
schtasks.exe /Delete /TN "SOC-LAB-PERSISTENCE" /F
```

Confirm removal:

```powershell
schtasks.exe /Query /TN "SOC-LAB-PERSISTENCE"
```

A successful cleanup should return an error indicating that the specified task cannot be found.

---

## 6. Isolation Validation

When the User Prompt appears:

### YES Path

1. Select `YES`.
2. Confirm that Tines calls the LimaCharlie isolation API.
3. Verify the endpoint network state in LimaCharlie.
4. Confirm that the endpoint cannot access normal network destinations.
5. Confirm that Slack reports:

```text
Isolation status: true
```

### NO Path

1. Select `NO`.
2. Confirm that no isolation API request is sent.
3. Verify that the endpoint retains network connectivity.
4. Confirm that Slack records the analyst decision.

### Rejoin Test

After an isolation test, issue a rejoin action from LimaCharlie and confirm that the endpoint returns to:

```text
Network Access: Allowed
```

---

## 7. Troubleshooting

### Detection Does Not Appear

Check:

- Rule status
- Sensor tag
- Sensor `Receiving` state
- Process event telemetry
- Correct `FILE_PATH` and `COMMAND_LINE` field paths
- D&R rule syntax

### Tines Does Not Receive the Detection

Check:

- Webhook URL
- Tines webhook events
- LimaCharlie output configuration
- Story status
- Detection payload structure

### Username Is Blank

This can occur when the event does not include `USER_NAME`. The workflow should display:

```text
Unknown / Not provided
```

### Isolation Remains Pending

Check the local LimaCharlie service:

```powershell
Get-Service rphcpsvc
```

Restart the service if required:

```powershell
Restart-Service rphcpsvc
```

Review the local status file:

```powershell
Get-Content "C:\ProgramData\limacharlie\hcp_hbs_status.json"
```

Verify that `last_update` changes over time before testing isolation again.

---

## 8. Evidence Collection

For each use case, capture:

1. The test command or simulated activity
2. The LimaCharlie detection
3. The Slack or email alert
4. The Tines User Prompt
5. The isolation decision and result

Before committing screenshots, redact:

- Organization ID
- Sensor ID
- External IP address
- Installation key
- API key
- Webhook URL
- Personal email address
- Detection URL
