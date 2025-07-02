---
title: "Virtual Machine Brute Force Detection"
date: 2025-07-01
categories: [Blue Team, Incident Response]
tags: [windows, sentinel, mssentinel, azure, bruteforce, detection]
---

# 🔍 Overview

> When entities (local or remote users, usually) attempt to log into a virtual machine, a log will be created on the local machine and then forwarded to Microsoft Defender for Endpoint under the DeviceLogonEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when the same entity fails to log into the same VM a given number of times within a certain time period. (i.e. 10 failed logons or more per 5 hours). 


## Tools Used
- **Cloud Platform:** Azure
- **SIEM:** Microsoft Sentinel
- **VM:** Windows 10

# Scenario 1: Virtual Machine Brute Force Detection

# Objective:

Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when the same Remote IP Address has failed to log in to the same local host (Azure VM) 10 times or more within the last 5 hours.

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image.png)

Testing the KQL Query that will be used in the Detection Rule:

```powershell
DeviceLogonEvents
| where ActionType == "LogonFailed" //Filter for failed logins
| where TimeGenerated > ago(5h) // Only consider events within the last 5 hours
| summarize FailedAttempts = count() by RemoteIP, ActionType, DeviceName, bin(TimeGenerated, 1h) // Group by remote IP, local host, and 1-hour time bins
| where FailedAttempts >= 50 // Filter for 10 or more failed login attempts
| project TimeGenerated, RemoteIP, ActionType, DeviceName, FailedAttempts
| order by TimeGenerated desc
```

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image1.png)

MITRE ATT&CK TTPs related to the KQL Query used above:

```powershell
T1110 – Brute Force  
> The query is looking for repeated failed authentication attempts (>=50), which indicates a brute-force attack against user credentials.

T1078 – Valid Accounts *(follow-up technique)*  
> While not directly observed here, the attacker’s goal in brute-force attacks is typically to obtain valid credentials. If successful, they may use this technique afterward.

T1040 – Network Sniffing *(optional and speculative)*  
> If combined with other techniques like packet capture to support credential discovery, though not shown in this query.

T1056.001 – Input Capture: Keylogging *(potential outcome of successful compromise)*  
> This would be a post-compromise method if the attacker used valid credentials obtained through brute force and installed a keylogger.

```

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image2.png)

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image3.png)

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image4.png)

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image5.png)

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image6.png)

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image7.png)

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image8.png)

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image9.png)

The rule is triggered

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image10.png)

Assign the incident to myself

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image11.png)

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image12.png)

Entities involved in Alert Triggering

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image13.png)

# Containment, Eradication, and Recovery

We can isolate the affected devices and run anti-virus scans within MDE.

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image14.png)

I ran a KQL Query to see which Remote IPs had failed login attempts that have met my prior criteria.

```powershell
DeviceLogonEvents
| where ActionType == "LogonFailed" //Filter for failed logins
| where TimeGenerated > ago(5h) // Only consider events within the last 5 hours
| summarize FailedAttempts = count() by RemoteIP, ActionType, DeviceName, bin(TimeGenerated, 1h) // Group by remote IP, local host, and 1-hour time bins
| where FailedAttempts >= 50 // Filter for 10 or more failed login attempts
| project TimeGenerated, RemoteIP, ActionType, DeviceName, FailedAttempts
| order by TimeGenerated desc
```

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image15.png)

Next, I ran a KQL Query to check if the violating Remote IPs had any successful login attempts

```powershell
DeviceLogonEvents
| where RemoteIP in ("80.94.95.54", "10.0.0.220", "10.0.0.8", "2.184.59.96")
| where ActionType  != "LogonFailed"
```

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image16.png)

Network Security Group (NSG) was locked down to prevent RDP attempts from the public internet. Policy was proposed to require this for all VMs going forward. 

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image17.png)

Updated the Incident Activity Log

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image18.png)

Closing the Incident

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image19.png)

Cleanup: Deleting the Detection Rule

![image.png](/assets/img/bluelabs/vm-bruteforce-detection/image20.png)
