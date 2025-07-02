---
title: "Devices Exposed to the Internet"
date: 2025-07-01
categories: [Blue Team, Threat Hunting, Incident Response]
tags: [windows, sentinal, threathunting]
---

> During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources. During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts.

## 🔍 Overview

# Scenario 1: Devices Exposed to the Internet

Finding Remote IPs that have attempted Failed Logins and Sorting by Most Attempts

```bash
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by RemoteIP
| order by Attempts desc
```

![image.png](/assets/img/bluelabs/1.png)

Searching for Successful Logons from the Top 7 Remote IPs from the Previous Query

```bash
let RemoteIPsInQuestion = dynamic(["10.0.0.8","185.224.3.219", "80.64.18.199", "176.65.150.72", "92.53.90.248", "80.249.131.239", "64.26.249.208"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

![image.png](image%201.png)

Machine windows-target-1 has been exposed to the internet for several days

```bash
DeviceInfo
| where DeviceName  == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

![image.png](image%202.png)

Searching for Failed Logins from Remote IPs to machine windows-target-1

```bash
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

![image.png](image%203.png)

Take the top 10 IPs with the most logon failures and see if any succeeded to logon

```bash
let RemoteIPsInQuestion = dynamic(["10.0.0.8","185.224.3.219", "80.64.18.199", "176.65.150.72", "92.53.90.248", "80.249.131.239", "94.26.249.208", "92.53.65.234", "185.170.144.3", "148.72.141.37"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

![image.png](image%204.png)

Look for any remote IP addresses who have had both successful and failed logons

```bash
// Investigate for potential brute force successes
let FailedLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedLogonAttempts = count() by ActionType, RemoteIP, DeviceName
| order by FailedLogonAttempts;
let SuccessfulLogons =  DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by ActionType, RemoteIP, DeviceName, AccountName
| order by SuccessfulLogons;
FailedLogons
| join SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
```

![image.png](image%205.png)

There were 0 successful logons by “labuser” to the “windows-target-1” machine in the last 30 days

```bash
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```

![image.png](image%206.png)

There were no failed logon attempts by “labuser” to the “windows-target-1” machine in the last 30 days

```bash
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| distinct AccountName
```

![image.png](image%207.png)

No Successful Logon Attempts by “labuser” to “windows-target-1” from time range of January 1st 2024 to June 28, 2025:

```bash
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

![image.png](image%208.png)

![image.png](image%209.png)

Though the device was exposed to the internet and clear brute force has taken place, there is no evidence of any brute force success or any unauthorized access from the legitimate labuser account.
