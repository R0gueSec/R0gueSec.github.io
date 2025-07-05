---
title: "Programmatic Remediation in Linux"
date: 2025-07-05
categories: [Blue Team, Vulnerability Management]
tags: [liunx, azure, tenable, bash, openssl, telnet]
---

# Programmatic Remediation in Linux

# Overview

> In this lab, I will demonstrate how to establish a baseline scan of a Linux machine, intentionally create vulnerabilities, and then automate the remediation of those vulnerabilities using bash scripts.
> 

## Tools Used

**Cloud Platform:** Azure

**Vulnerability Scanner:** Tenable

**Compliance Standard:** Linux DISA STIG

**VM:** Linux Ubuntu 

**Applications:** Bash, OpenSSL, Telnet

## Create an Authenticated Scan in Tenable

Create a Scan in Tenable

![](/assets/img/bluelabs/vuln-linux/image.png)

Choose “User Defined” and Select “Linux - Vulnerabilities + DISA STIG”

![](/assets/img/bluelabs/vuln-linux/image1.png)

![](/assets/img/bluelabs/vuln-linux/image2.png)

Name the scan, choose “LOCAL-SCAN-ENGINE-01” as the scanner, and use the VM’s internal IP address as the target. 

![](/assets/img/bluelabs/vuln-linux/image3.png)

Click on the Credentials blade, then Add Credentials, and choose Host

![](/assets/img/bluelabs/vuln-linux/image4.png)

Then choose SSH

![](/assets/img/bluelabs/vuln-linux/image5.png)

In Authentication Method, select password. Enter the username and password. For Elevate Privileges With, select su. Enter your username and password again in the SU LOGIN and ESCALATION PASSWORD fields. Then click on Save.

![](/assets/img/bluelabs/vuln-linux/image6.png)

## Conduct the Initial Scan

Now, Click on Save & Launch. 

![](/assets/img/bluelabs/vuln-linux/image7.png)

![](/assets/img/bluelabs/vuln-linux/image8.png)

## Intentionally Make Your VM Vulnerable

Log into the VM via SSH:

```powershell
ssh rogueuser@[IP]
```

### Install Telnet

```bash
sudo apt update
sudo apt install telnetd -y
sudo systemctl enable inetd.service
sudo systemctl start inetd.service

```

![](/assets/img/bluelabs/vuln-linux/image9.png)

Check the status of the service

```bash
sudo systemctl status inetd.service
```

![](/assets/img/bluelabs/vuln-linux/image10.png)

### Enable Remote Root Login

Run the following commands to enable remote root login.

```bash
sudo grep -q '^PermitRootLogin' /etc/ssh/sshd_config && sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart sshd

```

Set root password to “root”

```bash
sudo passwd root
```

![](/assets/img/bluelabs/vuln-linux/image11.png)

## Scan the VM again

In our second scan results, we can see the vulnerabilities for the default password of “root” for the root account, the OpenSSL version vulnerabilities, and the unencrypted telnet server. 

![](/assets/img/bluelabs/vuln-linux/image12.png)

## Remediate the Vulnerabilities

We will use the following scripts to remediate the three vulnerabilities. 

### Uninstall Telnet

[lognpacific-public/automation/remediation-Telnet-Remove.sh at main · joshmadakor1/lognpacific-public](https://github.com/joshmadakor1/lognpacific-public/blob/main/automation/remediation-Telnet-Remove.sh)

FILE: **remediation-Telnet-Remove.sh**

```bash
#!/bin/bash

# Stop the inetd service
sudo systemctl stop inetd.service

# Disable the inetd service to prevent it from starting at boot
sudo systemctl disable inetd.service

# Remove the telnetd package completely, including its configuration files
sudo apt remove --purge telnetd -y

# Remove the inetutils-inetd package completely, including its configuration files
sudo apt remove --purge inetutils-inetd -y

# Remove any unused dependencies that were installed with telnetd or inetutils-inetd
sudo apt autoremove -y

# Update the package lists to ensure they are current
sudo apt update

# Download the script
# wget https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/main/automation/remediation-Telnet-Remove.sh --no-check-certificate

# Make the script executable:
# chmod +x remediation-Telnet-Remove.sh

# Execute the script:
# ./remediation-Telnet-Remove.sh
```

Download the script

```bash
wget https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/automation/remediation-Telnet-Remove.sh
```

![](/assets/img/bluelabs/vuln-linux/image13.png)

Add execution rights to the script once it is downloaded:

```bash
chmod +x remediation-Telnet-Remove.sh
```

![](/assets/img/bluelabs/vuln-linux/image14.png)

Run the script

```bash
./remediation-Telnet-Remove.sh
```

![](/assets/img/bluelabs/vuln-linux/image15.png)

### Change Root Password from Default

[lognpacific-public/automation/remediation-root-password.sh at main · joshmadakor1/lognpacific-public](https://github.com/joshmadakor1/lognpacific-public/blob/main/automation/remediation-root-password.sh)

FILE: remediation-root-password.sh

```bash
#!/bin/bash
echo -e "Cyberlab123!\nCyberlab123!" | sudo passwd root

# This will delete the file after you're done so it doesn't store the password on the local system
# There are better ways to go about this, but this is just a proof of concept to remediate this particular vulnerability.
rm remediation-root-password.sh

# Download the script
# wget https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/main/automation/remediation-root-password.sh --no-check-certificate

# Make the script executable:
# chmod +x remediation-root-password.sh

# Execute the script:
# ./remediation-root-password.sh
```

Download the script

```bash
wget https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/automation/remediation-root-password.sh
```

![](/assets/img/bluelabs/vuln-linux/image16.png)

Add execution rights to the script

```bash
chmod +x remediation-root-password.sh
```

![](/assets/img/bluelabs/vuln-linux/image17.png)

Execute the script

```bash
./remediation-root-password.sh
```

![](/assets/img/bluelabs/vuln-linux/image18.png)

### Update OpenSSL to version 3.0.5

[lognpacific-public/automation/remediation-openssl-3.0.5-install.sh at main · joshmadakor1/lognpacific-public](https://github.com/joshmadakor1/lognpacific-public/blob/main/automation/remediation-openssl-3.0.5-install.sh)

FILE: **remediation-openssl-3.0.5-install.sh**

```bash
#!/bin/bash

echo "Installing dependencies..."
sudo apt update
sudo apt install build-essential checkinstall zlib1g-dev -y

# Download and extract OpenSSL 3.0.5
echo "Downloading and extracting OpenSSL 3.0.5..."
sudo wget -P /usr/local/src https://www.openssl.org/source/openssl-3.0.5.tar.gz
cd /usr/local/src
sudo tar -xf openssl-3.0.5.tar.gz

# Compile and install OpenSSL
echo "Configuring, compiling, and installing OpenSSL..."
cd openssl-3.0.5
sudo ./config
sudo make
sudo make install

# Set library path for OpenSSL libraries
echo "Setting library paths..."
echo "/usr/local/lib64" | sudo tee /etc/ld.so.conf.d/openssl-3.conf
sudo ldconfig

# Confirm the installation
echo "Installation confirmed with the following version:"
/usr/local/bin/openssl version

# Reboot to apply all changes
echo "Rebooting system to apply changes..."
sudo reboot

# Download the script
# wget https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/main/automation/remediation-openssl-3.0.5-install.sh --no-check-certificate

# Make the script executable:
# chmod +x remediation-openssl-3.0.5-install.sh

# Execute the script:
# ./remediation-openssl-3.0.5-install.sh
```

Download the script

```bash
wget https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/automation/remediation-openssl-3.0.5-install.sh
```

Add execution rights to the script

```bash
chmod +x remediation-openssl-3.0.5-install.sh
```

![](/assets/img/bluelabs/vuln-linux/image19.png)

Run the script

```bash
./remediate-openssl-3.0.5.install.sh
```

![](/assets/img/bluelabs/vuln-linux/image20.png)

At the end of the script, the script causes the VM to restart, so your SSH connection will become disconnected.

## Scan the VM after Remediation

![](/assets/img/bluelabs/vuln-linux/image21.png)

The scan results indicate that the vulnerabilities that we had created - the default root password of “root”, the vulnerable telnet server, and the vulnerable version of OpenSSL - have all been remediated. 

## Conclusion

As you seen in the scans above, the intentionally created vulnerabilities have been remediated. Automating the remediations using bash scripts allows us to not only efficiently remediate these vulnerabilities, but allows the remediations to occur at scale and repeatedly if needed.
