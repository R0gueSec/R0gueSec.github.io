---
title: "Programmatic Remediation in Windows"
date: 2025-07-05
categories: [Blue Team, Vulnerability Management]
tags: [windows, azure, tenable, powershell]
---

# Overview

> In this lab, I will cover how to use Tenable to scan a Windows 10 machine, then intentionally create vulnerabilities, automate the remediation of those vulnerabilities using PowerShell scripts, and then confirming the remediations by scanning the machine with Tenable again.
> 

## Tools Used

**Cloud Platform:** Azure

**Vulnerability Scanner:** Tenable

**Compliance Standard:** Windows 10 DISA STIG

**VM:** Windows 10 22H2

**Applications:** PowerShell, Firefox

## Preparing the Windows 10 Virtual Machine

Search bar > “Run” > “wf.msc

![image](/assets/img/bluelabs/vuln-windows/image.png)

Click on “Windows Defender Firewall Properties”

![image](/assets/img/bluelabs/vuln-windows/image1.png)

Turn off the firewall for “Domain Profile”, “Private Profile”, and “Public Profile”

![image](/assets/img/bluelabs/vuln-windows/image2.png)

Open PowerShell as Administrator.

Run the following command to enable remote administrative access:

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord -Force
```

![image](/assets/img/bluelabs/vuln-windows/image3.png)

## Create an Authenticated Windows 10 DISA STIG Scan in Tenable

In Tebable, click Create Scan

![image](/assets/img/bluelabs/vuln-windows/image4.png)

![image](/assets/img/bluelabs/vuln-windows/image5.png)

Name the scan, choose `LOCAL-SCAN-ENGINE-01` as the scanner, and put your VM’s internal IP in the Target box.

![image](/assets/img/bluelabs/vuln-windows/image6.png)

Click on the Credentials link and Select “Host” then “Windows”

![image](/assets/img/bluelabs/vuln-windows/image7.png)

![image](/assets/img/bluelabs/vuln-windows/image8.png)

Run the initial scan

![image](/assets/img/bluelabs/vuln-windows/image9.png)

Initial Scan Results:

![image](/assets/img/bluelabs/vuln-windows/image10.png)

## Intentionally Create Vulnerabilities in the Windows 10 VM

### Install an Old and Insecure Version of Firefox

![image](/assets/img/bluelabs/vuln-windows/image11.png)

![image](/assets/img/bluelabs/vuln-windows/image12.png)

### Enable SMBv1

In the Run menu, type `appwiz.cpl`

![image](/assets/img/bluelabs/vuln-windows/image13.png)

Click on “Turn Windows Features On or Off”

![image](/assets/img/bluelabs/vuln-windows/image14.png)

Scroll down until you find `SMB 1.0/CIFS File Sharing Support` and click the main box and all the boxes that fall under it. Select “Ok” Don’t restart yet until the next step.

![image](/assets/img/bluelabs/vuln-windows/image15.png)

### Enable discouraged cryptographic protocols: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1

On the VM, download the script at the following link:

[lognpacific-public/automation/toggle-protocols.ps1 at main · joshmadakor1/lognpacific-public](https://github.com/joshmadakor1/lognpacific-public/blob/main/automation/toggle-protocols.ps1)

In PowerShell, use Notepad to create a new .ps1 file:

```powershell
notepad toggle-protocols.ps1
```

Copy and paste the script into the Notepad window.

FILE: toggle-protocols.ps1

```powershell
<#
.SYNOPSIS
    Toggles cryptographic protocols (secure vs insecure) on the system.
    Please test thoroughly in a non-production environment before deploying widely.
    Make sure to run as Administrator or with appropriate privileges.

.NOTES
    Author        : Josh Madakor
    Date Created  : 2024-09-09
    Last Modified : 2024-09-09
    Version       : 1.0

.TESTED ON
    Date(s) Tested  : 2024-09-09
    Tested By       : Josh Madakor
    Systems Tested  : Windows Server 2019 Datacenter, Build 1809
    PowerShell Ver. : 5.1.17763.6189

.USAGE
    Set [$makeSecure = $true] to secure the system
    Example syntax:
    PS C:\> .\toggle-protocols.ps1 
#>
 
# Variable to determine if we want to make the computer secure or insecure
$makeSecure = $true

# Check if the script is run as Administrator
function Check-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main script
if (-not (Check-Admin)) {
    Write-Error "Access Denied. Please run with Administrator privileges."
    exit 1
}

# SSL 2.0 settings
$serverPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
$clientPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"

if ($makeSecure) {
    New-Item -Path $serverPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 2.0 has been disabled."
} else {
    New-Item -Path $serverPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 2.0 has been enabled."
}

# SSL 3.0 settings
$serverPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
$clientPathSSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"

if ($makeSecure) {
    New-Item -Path $serverPathSSL3 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL3 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL3 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL3 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL3 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL3 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 3.0 has been disabled."
} else {
    New-Item -Path $serverPathSSL3 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL3 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL3 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL3 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL3 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL3 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 3.0 has been enabled."
}

# TLS 1.0 settings
$serverPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
$clientPathTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"

if ($makeSecure) {
    New-Item -Path $serverPathTLS10 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS10 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS10 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS10 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS10 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS10 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.0 has been disabled."
} else {
    New-Item -Path $serverPathTLS10 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS10 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS10 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS10 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS10 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS10 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.0 has been enabled."
}

# TLS 1.1 settings
$serverPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
$clientPathTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"

if ($makeSecure) {
    New-Item -Path $serverPathTLS11 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS11 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS11 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS11 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS11 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS11 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.1 has been disabled."
} else {
    New-Item -Path $serverPathTLS11 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS11 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS11 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS11 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS11 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS11 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.1 has been enabled."
}

# TLS 1.2 settings
$serverPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
$clientPathTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

if ($makeSecure) {
    New-Item -Path $serverPathTLS12 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS12 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS12 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS12 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS12 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS12 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.2 has been enabled."
} else {
    New-Item -Path $serverPathTLS12 -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS12 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathTLS12 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathTLS12 -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS12 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathTLS12 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "TLS 1.2 has been disabled."
}

Write-Host "Please reboot for settings to take effect." 
```

![image](/assets/img/bluelabs/vuln-windows/image16.png)

Save the file.

![image](/assets/img/bluelabs/vuln-windows/image17.png)

Run the PowerShell script you just made.

```powershell
.\toggle-protocols.ps1
```

Open up the script and change `$makeSecure = $true` to `$makeSecure = $false` 

![image](/assets/img/bluelabs/vuln-windows/image18.png)

![image](/assets/img/bluelabs/vuln-windows/image19.png)

Now reboot the machine:

![image](/assets/img/bluelabs/vuln-windows/image20.png)

Wait a few minutes and log into the VM again via RDP before commencing to the next step. You want to make sure the VM is running again before scanning a second time.

## Run the Authenticated Scan Again

We will run the scan again to find the vulnerabilities we just intentionally made on the machine. 

![image](/assets/img/bluelabs/vuln-windows/image21.png)

![image](/assets/img/bluelabs/vuln-windows/image22.png)

## Use PowerShell to Remediate the Vulnerabilities

[lognpacific-public/automation/remediation-FireFox-uninstall.ps1 at main · joshmadakor1/lognpacific-public](https://github.com/joshmadakor1/lognpacific-public/blob/main/automation/remediation-FireFox-uninstall.ps1)

![image](/assets/img/bluelabs/vuln-windows/image23.png)

[lognpacific-public/automation/remediation-SMBv1.ps1 at main · joshmadakor1/lognpacific-public](https://github.com/joshmadakor1/lognpacific-public/blob/main/automation/remediation-SMBv1.ps1)

![image](/assets/img/bluelabs/vuln-windows/image24.png)

Open the `toggle-protocols.ps1` file and change `$makeSecure = $false` back to `$makeSecure = $true` 

![image](/assets/img/bluelabs/vuln-windows/image25.png)

Run the script.

```powershell
powershell -ep bypass
```

```powershell
.\toggle-protocols.ps1
```

![image](/assets/img/bluelabs/vuln-windows/image26.png)

Now you will notice that TLS 1.2 is enabled and all the prior SSL/TLS versions are disabled. 

Run the other two scripts.

```powershell
powershell -ep bypass
```

```powershell
.\remediation-Firefox-uninstall.ps1
```

```powershell
.\remediation-SMBv1.ps1
```

![image](/assets/img/bluelabs/vuln-windows/image27.png)

Reset the VM.

![image](/assets/img/bluelabs/vuln-windows/image28.png)

## Run the Authenticated Scan After Remediating the Vulnerabilities

![image](/assets/img/bluelabs/vuln-windows/image29.png)

## Observe the Results and Compare

![image](/assets/img/bluelabs/vuln-windows/image30.png)

The scan confirms that the vulnerabilities have been remediated. 

## Conclusion

As the final scan indicates, the vulnerabilities were remediated after we used the PowerShell scripts. Automated remediation allows for efficient remediation and we can save the scripts for later use should we need to remediate at scale or repeatedly.
