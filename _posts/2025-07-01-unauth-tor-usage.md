---
title: "Unauthorized Tor Usage"
date: 2025-07-01
categories: [Blue Team, Threat Hunting, Incident Response]
tags: [windows, sentinel, threathunting, edr, msdefenderforendpoint, mssentinel, azure, tor, unauthorizedapplications]
---

# 🔍 Overview

> Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.


## Tools Used
- **Cloud Platform:** Azure
- **EDR:** Microsoft Defender for Endpoint
- **SIEM:** Microsoft Sentinel
- **VM:** Windows 10

# Performing the Threat Hunt

# **Threat Hunt Report (Unauthorized TOR Usage)**

Detection of Unauthorized TOR Browser Installation and Use on Workstation: threat-hunting-

## **Example Scenario:**

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

---

## **High-Level TOR related IoC Discovery Plan:**

1. Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events
2. Check DeviceProcessEvents for any signs of installation or usage
3. Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports

---

## **Steps Taken**

1. Searched the DeviceFileName table for ANY file that had the string “tor” in it and discovered that at  2025-06-30T15:37:03.0494104Z the user “rogueuser” downloaded a tor installer and did something that resulted in many tor-related files being copied to the desktop. The user also created a file called “tor-shopping-list.txt” on the desktop at 2025-06-30T16:48:58.605783Z. 

The KQL Query used to locate events was: 

```powershell
DeviceFileEvents
| where DeviceName == "threat-hunting-"
| where InitiatingProcessAccountName == "rogueuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-30T15:37:03.0494104Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

![image.png](/assets/img/bluelabs/unauth-tor-usage/image.png)

![image.png](/assets/img/bluelabs/unauth-tor-usage/image1.png)

1. Searched the DeviceProcessEvents table for any ProcessCommandLine that contains the string “tor-browser-windows-x86_64-portable-14.5.4.exe”. Based on the logs returned, at 2025-06-30T15:46:22.6735856Z, an employee using the “rogueuser” account on the “threat-hunting-” device ran the file tor-browser-windows-x86_64-portable-14.5.4.exe, using the command “tor-browser-windows-x86_64-portable-14.5.4.exe /S” to trigger a silent installation. Query used to locate events: 

```powershell
DeviceProcessEvents
| where DeviceName == "threat-hunting-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
```

![image.png](/assets/img/bluelabs/unauth-tor-usage/image2.png)

![image.png](/assets/img/bluelabs/unauth-tor-usage/image3.png)

1. Searched the DeviceProcessEvents table for any indication that user account “rogueuser” actually opened the tor browser. There is evidence that he did open it at 2025-06-30T15:46:59.8022371Z. This is the query used to locate the events:

```powershell
DeviceProcessEvents
| where DeviceName == "threat-hunting-"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```

![image.png](/assets/img/bluelabs/unauth-tor-usage/image4.png)

![image.png](/assets/img/bluelabs/unauth-tor-usage/image5.png)

1. Searched the DeviceNetworkEvents table for any indication of the tor browser being used to establish a connection using any of the ports it is known to use (9001, 9040, 9050, 9051, and 9150).

At 8:47 AM on June 30, 2025, a user named rogueuser on the device named threat-hunting- ran the Tor Browser from this file path:

```powershell
C:\Users\rogueuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
```

This program (tor.exe) attempted to connect to a remote server with the IP address 192.121.108.237 over port 9001, and the destination URL was:

```powershell
[https://www.65ctbb2wa47ay54qw6rmk.com](https://www.65ctbb2wa47ay54qw6rmk.com/)
```

This was the KQL Query used:

```powershell
DeviceNetworkEvents
| where DeviceName == "threat-hunting-"
| where InitiatingProcessAccountName  != "system"
| where RemotePort in ("9001", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessFileName,  RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc 
```

![image.png](/assets/img/bluelabs/unauth-tor-usage/image6.png)

![image.png](/assets/img/bluelabs/unauth-tor-usage/image7.png)

---

## **Chronological Events**

**1. [2025-06-30 08:47:37 AM] – Outbound TOR Connection Detected**

- Device: `threat-hunting-`
- User: `rogueuser`
- Process: `tor.exe`
- File Path: `C:\Users\rogueuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- Remote IP: `192.121.108.237`
- Remote Port: `9001` (Known TOR entry node port)
- Remote URL: `https://www.65ctbb2wa47ay54qw6rmk.com`
- **Significance**: Indicates active TOR usage, likely via a TOR entry node.

---

**2. [2025-06-30 03:37:03 PM] – TOR Installation Files Written to Desktop**

- Device: `threat-hunting-`
- User: `rogueuser`
- Several TOR-related files appeared in the Desktop folder
- **File Example**: `tor-browser-windows-x86_64-portable-14.5.4.exe`
- **Significance**: Suggests the user downloaded and unpacked the portable TOR bundle.

---

**3. [2025-06-30 03:46:22 PM] – Silent TOR Browser Installation Executed**

- Device: `threat-hunting-`
- User: `rogueuser`
- Process: `tor-browser-windows-x86_64-portable-14.5.4.exe /S`
- Action: Silent install of TOR browser (no user prompts)
- **Significance**: Indicates intent to avoid detection by installing TOR quietly.

---

**4. [2025-06-30 03:46:59 PM] – TOR Executable Launched**

- Device: `threat-hunting-`
- User: `rogueuser`
- Process: `tor.exe`
- **Significance**: Confirms that the TOR browser was actively launched post-installation.

---

**5. [2025-06-30 04:48:58 PM] – "tor-shopping-list.txt" Created on Desktop**

- Device: `threat-hunting-`
- User: `rogueuser`
- File: `tor-shopping-list.txt`
- **Significance**: Possibly contains a list of intended sites or actions to take on the TOR network.

---

## **Summary**

- A user (`rogueuser`) on the `threat-hunting-` device downloaded, silently installed, and executed the TOR browser on June 30, 2025.
- Active network communication occurred with a known TOR entry node (port 9001), confirming unauthorized usage.
- Supporting artifacts such as `.exe` files and a text file labeled `tor-shopping-list.txt` reinforce deliberate TOR activity.
- This behavior bypasses standard security monitoring and poses a high risk for data exfiltration, policy violations, or anonymous access to the Dark Web.

---

## **Response Taken**

The device was isolated and the user's direct manager was notified.
