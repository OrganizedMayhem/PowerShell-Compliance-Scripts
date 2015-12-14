##This script backs up registry hives before any keys are added or updated and then sets the recommended values to meet HIPAA compliance##


#Creates Green HIPAA Directory for Reg Backups
#mkdir C:\NIST\

#Backs Up Registry before changes are made


## 1.21 1198  Audit: Audit the use of backup and restore privilege setting (Critical)
$registrypath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$name = "FullPrivilegeAuditing"
$value = 00

 
# Checks if key already exists
If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## 1.24 1358 Retention Method for Application Log
$registrypath = "HKLM:\System\CurrentControlSet\Services\Eventlog\Application"
$name = "DefaultInboundAction"
$value = 0

# Checks if key already exists
If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## 1.25 1391 Recover Console: Allow Automatic Administrative Logon

$registrypath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
$name = "SecurityLevel"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (1.26) 1392 Recovery console: Allow floppy copy and access to all drives and all folders

$registrypath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
$name = "SetCommand"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (1.35) 4050 Status of the 'SQL Server VSS Writer' service
#Expected value is 4 (Disabled), Currently Set to Automatic (2)
$registrypath = "HKLM:\System\CurrentControlSet\Services\SqlWriter"
$name = "Start"
$value = 2

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (2.1) 1156 Status of the 'Audit: Shut Down system immediately if unable to log security audits
#
$registrypath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$name = "CrashOnAuditFail"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (2.2) 1170 MSS: (AutoReboot) Allow Windows to automatically restart after a system crash
# 0 = Disabled, 1 = Enabled, Key not found are all acceptable
$registrypath = "HKLM:\System\CurrentControlSet\Control\CrashControl"
$name = "AutoReboot"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (2.6) 3786 Status of the Microsoft 'Volume Shadow Copy Service Provider' service
# Automatic (2), Automatic Delayed Start (21), Manual (3), Disabled (4) - All are acceptable
$registrypath = "HKLM:System\CurrentControlSet\Services\swprv"
$name = "Start"
$value = 3

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (2.9) 8441 Status of the 'Hyper-V Volume Shadow Copy Requestor' Service
# Automatic (2), Automatic Delayed Start (21), Manual (3), Disabled (4), *Manual is expected
$registrypath = "HKLM:System\CurrentControlSet\Services\vmicvss"
$name = "Start"
$value = 3

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

#Create fssagent Key if it doesnt exist
$registrypath = "HKLM:\System\CurrentControlSet\Services\fssagent"


## (2.10) 8457  Microsoft File Server Shadow Copy Agent
# Automatic (2), Automatic Delayed Start (21), Manual (3), Disabled (4) - All are acceptable
$registrypath = "HKLM:\System\CurrentControlSet\Services\fssagent"
$name = "Start"
$value = 3

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

#Create ddpvssvc Key if it doesnt exist
$registrypath = "HKLM:\System\CurrentControlSet\Services\ddpvssvc"


## (2.11) 8686  Data Duplication Volume Shadow Copy
# Automatic (2), Automatic Delayed Start (21), Manual (3), Disabled (4) - All are acceptable
$registrypath = "HKLM:\System\CurrentControlSet\Services\ddpvssvc"
$name = "Start"
$value = 4

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (4.4) 3724 Performance Logs and Alerts service
# (3) is expected
$registrypath = "HKLM:\System\CurrentControlSet\Services\pla"
$name = "Start"
$value = 3

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }


## (4.73) 3731 'System Event Notification' service
# Expected Value is Automatic (2)
$registrypath = "HKLM:\System\CurrentControlSet\Services\SENS"
$name = "Start"
$value = 2

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (4.74) 3962 Windows Firewall: Display a notification (Domain)
#
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
$name = "DisableNotifications"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (4.75) 3964 Status of the 'Windows Firewall: Display a notification (Private)' setting
#
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$name = "DisableNotifications"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (4.76) 3965 Windows Firewall: Display a notification (Public)
#
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$name = "DisableNotifications"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

##(11.42) 3927 Install Updates and Shut Down' option within the 'Shut Down Windows Dialog Box Setting

$registrypath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
$name = "NoAUShutdownOption"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

##  (11.45) 7529 Windows 'Automatic Updates' (WSUS) setting

$registrypath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
$name = "AUOptions"
$value = 3

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

##  (13.4) 3920 Turn off Internet download for Web publishing and online ordering wizards

$registrypath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$name = "NoWebServices"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## ##  (13.4) 3920 Turn off Internet download for Web publishing and online ordering wizards
$registrypath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$name = "NoWebServices"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (13.5) 3922 Turn off downloading of print drivers over HTTP
$registrypath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
$name = "DisableWebPnPDownload"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (14.28) 4156 Status of the 'Notify antivirus programs when opening attachments' Group Policy
$registrypath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
$name = "ScanWithAntiVirus"
$value = 3

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }



## (14.50) 8188 Status of the 'Boot-Start Driver Initialization Policy' setting
# Good, Unknown and bad but critical (3) is expected
$registrypath = "HKLM:\System\CurrentControlSet\Policies\EarlyLaunch"
$name = "DriverLoadPolicy"
$value = 3

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $valuee
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

#Create Explorer Key under Windows Policies
$registrypath = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"


## (14.52) 8273 Turn off Data Execution Prevention for Explorer
# Disabled (0), Enabled (1), Not configured. All are acceptable
$registrypath = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
$name = "NoDataExecutionPrevention"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (17.1) 1181 Status of the 'Simple Network Management Protocol (SNMP)' service (Windows)
# Disabled (4) or not configured are the expected settings
$registrypath = "HKLM:\System\CurrentControlSet\Services\SNMP"
$name = "Start"
$value = 4

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (17.8) 8233 Network Security:Restrict NTLM: Audit Incoming NTLM Traffic
# Disabled (0), Enable Auditing for Domain Accounts (1), Enable Auditing for all accounts (2), Not configured...All are acceptable
$registrypath = "HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0"
$name = "AutidReceivingNTLMTraffic"
$value = 2

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (17.9) 8234 Network Security:Restrict NTLM: Audit Incoming NTLM Authentication in this Domain
# Disable (0), Enable for Domain accounts to domain servers (1), Enable for Domain Accounts (3), Enable for Domain Servers (5), Enable All (7)..all acceptable
$registrypath = "HKLM:\System\CurrentControlSet\Services\NetLogon\Parameters"
$name = "AuditNTLMInDomain"
$value = 7

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (17.11) 8244 Configure 'Network Security:Restrict NTLM: NTLM authentication in this domain'
# Must be set. Disable (0), Deny for domain acct to domain servers (1), Deny for domain accts (3), Deny for Domain Servers (5), Deny all (7)
$registrypath = "HKLM:\System\CurrentControlSet\Services\NetLogon\Parameters"
$name = "RestrictNTLMInDomain"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (18.1) 1463 MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning
# 
$registrypath = "HKLM:\System\CurrentControlSet\Services\Eventlog\Security"
$name = "WarningLevel"
$value = 45

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }


##  (20.2) 4741 Status of the 'MSS: (DisableIPSourceRoutingIPv6) IP source routing protection level (protects against packet spoofing)'
# 
$registrypath = "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters"
$name = "DisableIPSourceRouting"
$value = 2

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }


## (20.17) 1172 MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
# 
$registrypath = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
$name = "DisableIPSourceRouting"
$value = 2

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (20.18) 1193 MSS: Allow ICMP redirects to override OSPF generated routes (EnableICMPRedirect)
# 
$registrypath = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
$name = "EnableICMPRedirect"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }


## (20.27) 8243 Configure Network Security:Restrict NTLM: Outgoing NTLM traffic to remote servers
#  Allow All (0), Audit all (1), Deny All(2), Not configured, are all acceptable

$registrypath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
$name = "RestrictSendingNTLMTraffic"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (20.29) 1177 Enable IPSec to protect Kerberos RSVP Traffic (NoDefaultExempt)' registry
$registrypath = "HKLM:\System\CurrentControlSet\Services\IPSec"
$name = "NoDefaultExempt"
$value = 

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (20.30) 1184 MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway Access (Could lead to DoS)
# Disabled (0), Enabled (1), Enabled only if DHCP sends the Perform Router Discovery Option (2).. All are acceptable inc not configured
$registrypath = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
$name = "PerformRouterDiscovery"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (20.32) 1195 MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from the 'WINS servers
# 
$registrypath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
$name = "NoNameReleaseOnDemand"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (20.38) 1462 MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds (300,000 is recommended)
# 
$registrypath = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
$name = "KeepAliveTime"
$value = 300000

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (20.40) 4742 MSS: (TCPMaxDataRetransmissions) IPv6 How many times unacknowledged data is retransmitted
# Recommended setting is 1-3
$registrypath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$name = "TCPMaxDataRetransmissions"
$value = 2

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (20.43) 1449 Status of the 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 = Rec, 5 = Default)
# 
$registrypath = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
$name = "TcpMaxDataRetransmissions"
$value = 2

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }
  

## (21.7) 3963 Status of the 'Windows Firewall: Apply local connection security rules (Private)'
# NIST, HIPAA. 'Key not found' or Yes are required to pass
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$name = "AllowLocalIPssecPolicyMerge"
$value = 

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.8) 3966 Status of the 'Windows Firewall: Apply local connection security rules (Public)
# HIPAA, NIST
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$name = "AllowLocalIpsecPolicyMerge"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.15) 4058 Status of the 'Windows Network List' service
# Expected Values to Pass (2-Automatic,21 - Automatic-Delayed, 3-Manual)
$registrypath = "HKLM:\SYSTEM\CurrentControlSet\Services\netprofm"
$name = "Start"
$value = 3

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.28) 3945 Windows Firewall: Apply local firewall rules (Domain)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
$name = "AllowLocalPolicyMerge"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.29) 3950 Windows Firewall: Firewall state (Public)' 
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$name = "EnableFirewall"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.30) 3951 Windows Firewall: Firewall state (Private)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$name = "EnableFirewall"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.31) 3952 Windows Firewall: Firewall state (Domain)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
$name = "EnableFirewall"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.32) 3959 Status of the 'Windows Firewall: Apply local firewall rules (Private)' setting
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$name = "AllowLocalPolicyMerge"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.33) 3960 Windows Firewall: Apply local firewall rules (Public)
# Block (1), Allow (0) 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$name = "DefaultInboundAction"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.37) 3948 Windows Firewall: Inbound connections (Private)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$name = "DefaultInboundAction"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.38) 3949 Status of the 'Windows Firewall: Inbound connections (Domain)' setting
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
$name = "DefaultInboundAction"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.39) 5261 Windows Firewall: Allow unicast response (Private)
# 
$registrypath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$name = "DisableUnicastResponsesToMulticastBroadcast"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.40) 5262 Windows Firewall: Allow unicast response (Public)
# 
$registrypath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$name = "DisableUnicastResponsesToMulticastBroadcast"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.49) 8157 Windows Firewall: Allow unicast response (Domain)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$name = "DefaultOutboundAction"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.52) 8164 Windows Firewall: Outbound connections (Public)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$name = "DefaultOutboundAction"
$value = 0

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.57) 8160 Windows Firewall: Log File Size (Private)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$name = "LogFileSize"
$value = 8160

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.58) 8161  Windows Firewall: Log file path and name (Private)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$name = "LogFilePath"
$value = "%systemroot%\system32\logfiles\firewall\Privatefw.log"

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.59) 8162 Windows Firewall: Log Successful Connections (Private)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$name = "LogSuccessfulConnections"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.60) 8163 Windows Firewall: Log dropped packets (Private)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$name = "LogDroppedpackets"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.61) 8165 Status of the 'Windows Firewall: Log dropped packets (Public)' setting
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$name = "LogDroppedPackets"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.62) 8166 Windows Firewall: Log file path and name (Public)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$name = "LogFilePath"
$value = "%systemroot%\system32\logfiles\firewall\Publicfw.log"

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.63) 8167 Status of the 'Windows Firewall: Log Successful Connections (Public)' setting
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$name = "LogSuccessfulConnections"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.64) 8168 Windows Firewall: Log File Size (Public)
# 
$registrypath = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$name = "LogFileSize"
$value = 16384

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.65) 8384 Windows Firewall Service
# 
$registrypath = "HKLM:\System\CurrentControlSet\Services\MpsSvc"
$name = "Start"
$value = 2

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.69) 5352 WLAN AutoConfig
# 
$registrypath = "HKLM:\System\CurrentControlSet\Services\WLANSVC"
$name = "Start"
$value = 2

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

## (21.75) 1153  Network Access: Do not allow Anonymous Enumeration of SAM Accounts & Shares
# 
$registrypath = "HKLM:\System\CurrentControlSet\Control\LSA"
$name = "RestrictAnonymous"
$value = 1

If(-not(Test-Path -Path $registrypath))
  {
      New-Item -Path $registrypath
      New-ItemProperty -Path $registrypath -Name $name -Value $value
  }
Else
  {
      Set-ItemProperty -Path $registrypath -Name $name -Value $value
  }

