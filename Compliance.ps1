#requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies recommended registry settings to help bring a Windows host into line with
    HIPAA-related hardening controls (control numbers map to Qualys Compliance scanner
    policy/control IDs - see README.md).

.DESCRIPTION
    Before making any changes, the script exports the HKLM\SYSTEM and HKLM\SOFTWARE
    hives to timestamped .reg files under -BackupPath. It then walks a data-driven list
    of controls ($controls below) and applies each one via Set-HipaaControl.

    Controls that are marked Enabled = $false are intentionally skipped. They were left
    disabled in the original script (commented out), typically because the recommended
    value was never filled in or because the setting needs environment-specific review
    before being applied. They are kept in the data for visibility/auditing, not applied.

    Supports -WhatIf / -Confirm since Set-HipaaControl implements ShouldProcess.

.PARAMETER BackupPath
    Directory where registry backups are written. Defaults to C:\Backup-Script.

.PARAMETER Control
    Optional filter. Only controls whose Control field matches one of these values
    (e.g. '1.21 1198') are applied. Defaults to all enabled controls.

.PARAMETER LogPath
    Optional path to a CSV file. If specified, the per-control results (one row per
    unique registry value touched) are written there for an audit trail. Not written
    under -WhatIf, since nothing was actually changed.

.EXAMPLE
    .\Compliance.ps1 -WhatIf
    Shows what would change without modifying the registry.

.EXAMPLE
    .\Compliance.ps1
    Backs up the registry and applies every enabled control.

.NOTES
    A few mechanical/typo bugs from the original per-control script were fixed while
    templatizing it, since they silently turned the affected control into a no-op by
    writing to a registry value name that doesn't exist:
      AutidReceivingNTLMTraffic -> AuditReceivingNTLMTraffic (17.8 8233)
      EveroneIncludesAnonymous  -> EveryoneIncludesAnonymous (21.81 1383)
      ValidateAdmin             -> ValidateAdminCodeSignatures (22.130 2603)
    Casing-only typos (registry value names are case-insensitive, so these were
    cosmetic) were also normalized to match the spelling used elsewhere in the same
    table: AllowLocalIPssecPolicyMerge, LogDroppedpackets, requiresecuritysignature.
    Control 43.16 (Telephony service) had Name = '3' instead of 'Start' - fixed, though
    it remains Enabled = $false since no compliant value was ever defined for it.
    Control 1.21 (FullPrivilegeAuditing) was writing the string '00' instead of the
    DWord 0 - corrected.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupPath = 'C:\Backup-Script',

    [string[]]$Control,

    [string]$LogPath
)

function Set-HipaaControl {
    <#
    .SYNOPSIS
        Creates (if needed) a registry key and sets a value on it, honoring -WhatIf/-Confirm.
        Returns $true if the value was actually written, $false if it was only previewed
        (-WhatIf) or -Confirm was declined, so callers can report an accurate status.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$RegistryPath,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        throw "No recommended value is defined for '$RegistryPath\$Name'; skipping."
    }

    if (-not (Test-Path -Path $RegistryPath)) {
        if ($PSCmdlet.ShouldProcess($RegistryPath, 'Create registry key')) {
            New-Item -Path $RegistryPath -Force | Out-Null
        }
    }

    if ($PSCmdlet.ShouldProcess("$RegistryPath\$Name", "Set value to '$Value'")) {
        New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -Force | Out-Null
        return $true
    }
    return $false
}

#region Registry backup
if ($PSCmdlet.ShouldProcess($BackupPath, 'Create backup directory')) {
    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
foreach ($hive in 'HKLM\SYSTEM', 'HKLM\SOFTWARE') {
    $backupFile = Join-Path $BackupPath ("{0}-{1}.reg" -f ($hive -replace '\\', '_'), $timestamp)
    if ($PSCmdlet.ShouldProcess($backupFile, "Export $hive")) {
        reg.exe export $hive $backupFile /y | Out-Null
    }
}
#endregion

#region Control definitions
$controls = @(
    [PSCustomObject]@{ Control = '1.21 1198'; Description = 'Audit: Audit the use of backup and restore privilege setting (Critical)'; RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'FullPrivilegeAuditing'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '1.24 1358'; Description = 'Retention Method for Application Log'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Eventlog\Application'; Name = 'DefaultInboundAction'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '1.25 1391'; Description = 'Recover Console: Allow Automatic Administrative Logon'; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'; Name = 'SecurityLevel'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '1.26 1392'; Description = 'Recovery console: Allow floppy copy and access to all drives and all folders'; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'; Name = 'SetCommand'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '1.35 4050'; Description = '''SQL Server VSS Writer'' service -- Expected value is 4 (Disabled), Currently Set to Automatic (2)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\SqlWriter'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '2.1 1156'; Description = '''Audit: Shut Down system immediately if unable to log security audits'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'; Name = 'CrashOnAuditFail'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '2.2 1170'; Description = 'MSS: (AutoReboot) Allow Windows to automatically restart after a system crash -- 0 = Disabled, 1 = Enabled, Key not found are all acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\CrashControl'; Name = 'AutoReboot'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '2.6 3786'; Description = 'Microsoft ''Volume Shadow Copy Service Provider'' service -- Automatic (2), Automatic Delayed Start (21), Manual (3), Disabled (4) - All are acceptable'; RegistryPath = 'HKLM:System\CurrentControlSet\Services\swprv'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '2.9 8441'; Description = '''Hyper-V Volume Shadow Copy Requestor'' Service -- Automatic (2), Automatic Delayed Start (21), Manual (3), Disabled (4), *Manual is expected'; RegistryPath = 'HKLM:System\CurrentControlSet\Services\vmicvss'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '2.10 8457'; Description = 'Microsoft File Server Shadow Copy Agent -- Automatic (2), Automatic Delayed Start (21), Manual (3), Disabled (4) - All are acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\fssagent'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '2.11 8686'; Description = 'Data Duplication Volume Shadow Copy -- Automatic (2), Automatic Delayed Start (21), Manual (3), Disabled (4) - All are acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\ddpvssvc'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '4.4 3724'; Description = 'Performance Logs and Alerts service -- (3) is expected'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\pla'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '4.73 3731'; Description = '''System Event Notification'' service -- Expected Value is Automatic (2)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\SENS'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '4.74 3962'; Description = 'Windows Firewall: Display a notification (Domain)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'DisableNotifications'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '4.75 3964'; Description = '''Windows Firewall: Display a notification (Private)'' setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'DisableNotifications'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '4.76 3965'; Description = 'Windows Firewall: Display a notification (Public)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'DisableNotifications'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '11.42 3927'; Description = 'Install Updates and Shut Down'' option within the ''Shut Down Windows Dialog Box Setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'NoAUShutdownOption'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '11.45 7529'; Description = 'Windows ''Automatic Updates'' (WSUS) setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'AUOptions'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '13.4 3920'; Description = 'Turn off Internet download for Web publishing and online ordering wizards'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoWebServices'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '13.5 3922'; Description = 'Turn off downloading of print drivers over HTTP'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableWebPnPDownload'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '14.28 4156'; Description = '''Notify antivirus programs when opening attachments'' Group Policy'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name = 'ScanWithAntiVirus'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '14.50 8188'; Description = '''Boot-Start Driver Initialization Policy'' setting -- Good, Unknown and bad but critical (3) is expected'; RegistryPath = 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch'; Name = 'DriverLoadPolicy'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '14.52 8273'; Description = 'Turn off Data Execution Prevention for Explorer -- Disabled (0), Enabled (1), Not configured. All are acceptable'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'; Name = 'NoDataExecutionPrevention'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '17.1 1181'; Description = '''Simple Network Management Protocol (SNMP)'' service (Windows) -- Disabled (4) or not configured are the expected settings'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\SNMP'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '17.8 8233'; Description = 'Network Security:Restrict NTLM: Audit Incoming NTLM Traffic -- Disabled (0), Enable Auditing for Domain Accounts (1), Enable Auditing for all accounts (2), Not configured...All are acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0'; Name = 'AuditReceivingNTLMTraffic'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '17.9 8234'; Description = 'Network Security:Restrict NTLM: Audit Incoming NTLM Authentication in this Domain -- Disable (0), Enable for Domain accounts to domain servers (1), Enable for Domain Accounts (3), Enable for Domain Servers (5), Enable All (7)..all acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\NetLogon\Parameters'; Name = 'AuditNTLMInDomain'; Value = 7; Enabled = $true }
    [PSCustomObject]@{ Control = '17.11 8244'; Description = 'Configure ''Network Security:Restrict NTLM: NTLM authentication in this domain'' -- Must be set. Disable (0), Deny for domain acct to domain servers (1), Deny for domain accts (3), Deny for Domain Servers (5), Deny all (7)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\NetLogon\Parameters'; Name = 'RestrictNTLMInDomain'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '18.1 1463'; Description = 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Eventlog\Security'; Name = 'WarningLevel'; Value = 45; Enabled = $true }
    [PSCustomObject]@{ Control = '20.2 4741'; Description = '''MSS: (DisableIPSourceRoutingIPv6) IP source routing protection level (protects against packet spoofing)'''; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'; Name = 'DisableIPSourceRouting'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '20.17 1172'; Description = 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'DisableIPSourceRouting'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '20.18 1193'; Description = 'MSS: Allow ICMP redirects to override OSPF generated routes (EnableICMPRedirect)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'EnableICMPRedirect'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '20.27 8243'; Description = 'Configure Network Security:Restrict NTLM: Outgoing NTLM traffic to remote servers -- Allow All (0), Audit all (1), Deny All(2), Not configured, are all acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'RestrictSendingNTLMTraffic'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '20.29 1177'; Description = 'Enable IPSec to protect Kerberos RSVP Traffic (NoDefaultExempt)'' registry'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\IPSec'; Name = 'NoDefaultExempt'; Value = $null; Enabled = $false }
    [PSCustomObject]@{ Control = '20.30 1184'; Description = 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway Access (Could lead to DoS) -- Disabled (0), Enabled (1), Enabled only if DHCP sends the Perform Router Discovery Option (2).. All are acceptable inc not configured'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'PerformRouterDiscovery'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '20.32 1195'; Description = 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from the ''WINS servers'; RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'; Name = 'NoNameReleaseOnDemand'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '20.38 1462'; Description = 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds (300,000 is recommended)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'KeepAliveTime'; Value = 300000; Enabled = $true }
    [PSCustomObject]@{ Control = '20.40 4742'; Description = 'MSS: (TCPMaxDataRetransmissions) IPv6 How many times unacknowledged data is retransmitted -- Recommended setting is 1-3'; RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name = 'TCPMaxDataRetransmissions'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '20.43 1449'; Description = '''MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 = Rec, 5 = Default)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'TcpMaxDataRetransmissions'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '21.7 3963'; Description = '''Windows Firewall: Apply local connection security rules (Private)'' -- NIST, HIPAA. ''Key not found'' or Yes are required to pass'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'AllowLocalIPsecPolicyMerge'; Value = $null; Enabled = $false }
    [PSCustomObject]@{ Control = '21.8 3966'; Description = '''Windows Firewall: Apply local connection security rules (Public) -- HIPAA, NIST'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'AllowLocalIpsecPolicyMerge'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.15 4058'; Description = '''Windows Network List'' service -- Expected Values to Pass (2-Automatic,21 - Automatic-Delayed, 3-Manual)'; RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\netprofm'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '21.28 3945'; Description = 'Windows Firewall: Apply local firewall rules (Domain)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'AllowLocalPolicyMerge'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.29 3950'; Description = 'Windows Firewall: Firewall state (Public)'''; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.30 3951'; Description = 'Windows Firewall: Firewall state (Private)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.31 3952'; Description = 'Windows Firewall: Firewall state (Domain)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.32 3959'; Description = '''Windows Firewall: Apply local firewall rules (Private)'' setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'AllowLocalPolicyMerge'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.33 3960'; Description = 'Windows Firewall: Apply local firewall rules (Public) -- Block (1), Allow (0)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'DefaultInboundAction'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.37 3948'; Description = 'Windows Firewall: Inbound connections (Private)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'DefaultInboundAction'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.38 3949'; Description = '''Windows Firewall: Inbound connections (Domain)'' setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'DefaultInboundAction'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.39 5261'; Description = 'Windows Firewall: Allow unicast response (Private)'; RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'DisableUnicastResponsesToMulticastBroadcast'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.40 5262'; Description = 'Windows Firewall: Allow unicast response (Public)'; RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'DisableUnicastResponsesToMulticastBroadcast'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.49 8157'; Description = 'Windows Firewall: Allow unicast response (Domain)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'DefaultOutboundAction'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '21.52 8164'; Description = 'Windows Firewall: Outbound connections (Public)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'DefaultOutboundAction'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '21.57 8160'; Description = 'Windows Firewall: Log File Size (Private)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogFileSize'; Value = 8160; Enabled = $true }
    [PSCustomObject]@{ Control = '21.58 8161'; Description = 'Windows Firewall: Log file path and name (Private)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogFilePath'; Value = '%systemroot%/system32/logfiles/firewall/Privatefw.log'; Enabled = $true }
    [PSCustomObject]@{ Control = '21.59 8162'; Description = 'Windows Firewall: Log Successful Connections (Private)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogSuccessfulConnections'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.60 8163'; Description = 'Windows Firewall: Log dropped packets (Private)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogDroppedPackets'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.61 8165'; Description = '''Windows Firewall: Log dropped packets (Public)'' setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogDroppedPackets'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.62 8166'; Description = 'Windows Firewall: Log file path and name (Public)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogFilePath'; Value = '%systemroot%/system32/logfiles/firewall/Publicfw.log'; Enabled = $true }
    [PSCustomObject]@{ Control = '21.63 8167'; Description = '''Windows Firewall: Log Successful Connections (Public)'' setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogSuccessfulConnections'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.64 8168'; Description = 'Windows Firewall: Log File Size (Public)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogFileSize'; Value = 16384; Enabled = $true }
    [PSCustomObject]@{ Control = '21.65 8384'; Description = 'Windows Firewall Service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\MpsSvc'; Name = 'Start'; Value = 2; Enabled = $false }
    [PSCustomObject]@{ Control = '21.69 5352'; Description = 'WLAN AutoConfig'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\WLANSVC'; Name = 'Start'; Value = 2; Enabled = $false }
    [PSCustomObject]@{ Control = '21.75 1153'; Description = 'Network Access: Do not allow Anonymous Enumeration of SAM Accounts & Shares'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\LSA'; Name = 'RestrictAnonymous'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.76 1169'; Description = 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)'; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'AutoAdminLogon'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '21.77 1196'; Description = 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires'; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon'; Name = 'ScreenSaverGracePeriod'; Value = 0; Enabled = $false }
    [PSCustomObject]@{ Control = '21.78 1197'; Description = '''Network access: Do not allow anonymous enumeration of SAM accounts'''; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\LSA'; Name = 'RestrictAnonymousSAM'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.79 1377'; Description = 'Interactive Logon: Require Domain Controller authentication to unlock'; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon'; Name = 'ForceUnlockLogon'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '21.80 1378'; Description = 'Interactive Logon: Smart Card Removal Behavior'; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon'; Name = 'ScRemoveOption'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '21.81 1383'; Description = 'Network Access: Let Everyone permissions apply to anonymous users'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\LSA'; Name = 'EveryoneIncludesAnonymous'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '21.82 1386'; Description = 'Network Access: Sharing and security model for local accounts'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\LSA'; Name = 'ForceGuest'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '21.83 1387'; Description = 'Network Security: LAN Manager Authentication Level'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Value = 5; Enabled = $true }
    [PSCustomObject]@{ Control = '21.84 1514'; Description = 'Restrictions for Unauthenticated RPC clients'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\RPC'; Name = 'RestrictRemoteClients'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.85 2605'; Description = 'User Account Control: Behavior of the elevation prompt for standard users'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorUser'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.88 3891'; Description = 'Always prompt for password upon connection'' setting (Terminal Services)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fPromptForPassword'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.89 5265'; Description = 'Network security: Allow LocalSystem NULL session fallback'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0'; Name = 'allownullsessionfallback'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '21.90 5266'; Description = 'Network security: Allow Local System to use computer identity for NTLM'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'; Name = 'UseMachineID'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.92 2606'; Description = 'User Account Control: Switch to the secure desktop when prompted for elevation'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'PromptOnSecureDesktop'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '21.127'; Description = 'Simple Network Management Protocol (SNMP) trap -- Default Value is 3 (Manual), Any start value passes NIST inc. Not set'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\SNMPTRAP'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '22.12 8435'; Description = '''Printer Extensions and Notifications'' -- Disabled (4) or not found pass'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\PrintNotify'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.13 8436'; Description = 'Hyper-V Time Synchronization -- Any set value passes. Default = Manual (3)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\vmictimesync'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '22.14 8442'; Description = 'Network Connectivity Assistant -- Set value was Manual, Disabled (4) is expected.'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\NcaSvc'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.15 8444'; Description = 'Credential Manager -- Set value was Manual (3)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\VaultSvc'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.16 8450'; Description = 'Hyper-V Heartbeat -- Any value passes, Set value was Manual (3)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\vmicheartbeat'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '22.17 8451'; Description = 'Active Directory Web -- Disabled or Not found are acceptable values'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\ADWS'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.18 8452'; Description = 'Hyper-V Data Exchange -- Disabled or not set are acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\vmickvpexchange'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.19 8453'; Description = 'Device Install'' Service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\DeviceInstall'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.20 8454'; Description = 'Hyper-V Remote Desktop Virtualization -- Any set value passes'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\vmicrdv'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '22.21 8455'; Description = 'Hyper-V Guest Shutdown -- Set value was manual (3)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\vmicshutdown'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.22 8456'; Description = 'DS Role Server'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\DsRoleSvc'; Name = 'Start'; Value = 4; Enabled = $false }
    [PSCustomObject]@{ Control = '22.23 8458'; Description = '''Windows Store'' Service (WSService) -- Set value was manual'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\WSService'; Name = 'Start'; Value = 4; Enabled = $false }
    [PSCustomObject]@{ Control = '22.24 8463'; Description = 'KDC Proxy Server -- Set value was manual (3)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\KPSSVC'; Name = 'Start'; Value = 4; Enabled = $false }
    [PSCustomObject]@{ Control = '22.25 8470'; Description = 'Microsoft iSCSI Software Target'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\WinTarget'; Name = 'Start'; Value = 4; Enabled = $false }
    [PSCustomObject]@{ Control = '22.28 1191'; Description = 'Remote Registry -- Set value was automatic (2)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\RemoteRegistry'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.43 1472'; Description = 'Network Connections'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Netman'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.44 1475'; Description = 'Remote Access Auto Connection Manager -- set value was manual'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\RasAuto'; Name = 'Start'; Value = 4; Enabled = $false }
    [PSCustomObject]@{ Control = '22.45 1476'; Description = 'Remote Access Connection Manager (RasMan) -- Set value was manual'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\RasMan'; Name = 'Start'; Value = 4; Enabled = $false }
    [PSCustomObject]@{ Control = '22.46 1479'; Description = 'Remote Procedure Call (RPC) Locater'' service -- set value was manual'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\RpcLocator'; Name = 'Start'; Value = 4; Enabled = $false }
    [PSCustomObject]@{ Control = '22.50 3720'; Description = 'IPSEC Services'' service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\PolicyAgent'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '22.52 2042'; Description = 'MSS: (AutoShareServer) Lanman ''Default administrative shares -- Any value passes Compliance'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'; Name = 'AutoShareServer'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '22.130 2603'; Description = '''User Account Control: Only elevate executables that are signed and validated'''; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ValidateAdminCodeSignatures'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '23.1 1052'; Description = '''Devices: Allowed to format and eject removable media'' setting (NTFS formatted devices)'; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon'; Name = 'AllocateDASD'; Value = $null; Enabled = $false }
    [PSCustomObject]@{ Control = '23.3 1183'; Description = '''Disable Autorun for all drives'' setting for the HKLM key'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\explorer'; Name = 'NoDriveTypeAutorun'; Value = 255; Enabled = $false }
    [PSCustomObject]@{ Control = '23.4 4067'; Description = '''Portable Device Enumerator'' service Failed'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\WPDBusEnum'; Name = 'Start'; Value = 3; Enabled = $false }
    [PSCustomObject]@{ Control = '24.38 7502'; Description = '[GPO-based] ''Application: Maximum log size'' setting (in KB) -- Greater than or equal to 32768'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'; Name = 'MaxSize'; Value = 32768; Enabled = $false }
    [PSCustomObject]@{ Control = '24.39 7503'; Description = '[GPO-based] ''Security: Maximum log size'' (in KB)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Value = 196608; Enabled = $true }
    [PSCustomObject]@{ Control = '24.40 7504'; Description = '[GPO-based] ''System: Maximum log size'' setting (in KB)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'; Name = 'MaxSize'; Value = 32768; Enabled = $true }
    [PSCustomObject]@{ Control = '24.41 9014'; Description = '''Setup: Maximum Log Size (KB)'' setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup'; Name = 'MaxSize'; Value = 32768; Enabled = $true }
    [PSCustomObject]@{ Control = '24.77 1367'; Description = '''Audit: Audit the access of global system objects'' setting'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'; Name = 'AuditBaseObjects'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '24.152 1964'; Description = '''Event Log'' service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\EventLog'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '24.153 3784'; Description = '''Windows Error Reporting'' service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\WerSvc'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '25.1 3899'; Description = '''Solicited Remote Assistance'' policy setting (Terminal Services)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fAllowToGetHelp'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '25.2 3900'; Description = 'Offer Remote Assistance'' setting (Terminal Services)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fAllowUnsolicited'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '27.1 1431'; Description = '''Domain controller: Allow server operators to schedule tasks'' setting'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'; Name = 'SubmitControl'; Value = 0; Enabled = $false }
    [PSCustomObject]@{ Control = '27.7 8443'; Description = '''Power'' Service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Power'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '28.1 3944'; Description = 'Application: Control Event Log behavior when the log file reaches its Max Size'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'; Name = 'Retention'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '28.6 9013'; Description = 'Setup: Control Event Log behavior when the log file reaches its max Size'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup'; Name = 'Retention'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '28.7 1048'; Description = 'Shutdown: Clear virtual memory pagefile'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'ClearPageFileAtShutdown'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '28.8 1362'; Description = 'Retention Method for Security Log'' setting'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\EventLog\Security'; Name = 'Retention'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '28.9 1365'; Description = 'Retention Method for System Log'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\EventLog\System'; Name = 'Retention'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '28.11 3942'; Description = 'System: Control Event Log behavior when the log file reaches its maximum size'' Group Policy setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'; Name = 'Retention'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '28.12 3943'; Description = 'Security: Control Event Log behavior when the log file reaches its maximum size'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'Retention'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '28.16 3797'; Description = 'Volume Shadow Copy Service (VSS)'''; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\VSS'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '29.1 1152'; Description = 'Allow undock without having to logon'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'UndockWithoutLogon'; Value = 2; Enabled = $false }
    [PSCustomObject]@{ Control = '29.2 1369'; Description = 'Shutdown: Allow system to be shut down without having to log on'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ShutdownwithoutLogon'; Value = 0; Enabled = $false }
    [PSCustomObject]@{ Control = '29.3 1433'; Description = 'Status of the ''Interactive logon: Require smart card'' setting'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ScForceOption'; Value = 0; Enabled = $false }
    [PSCustomObject]@{ Control = '29.7 8381'; Description = 'Smart card removal policy'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\SCPolicySvc'; Name = 'Start'; Value = 3; Enabled = $false }
    [PSCustomObject]@{ Control = '34.1 9043'; Description = 'Default Protections for Internet Explorer'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'; Name = 'ie'; Value = 'iexplore.exe'; Enabled = $false }
    [PSCustomObject]@{ Control = '34.2 9057'; Description = 'Status of the ''System ASLR'' setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\EMET\SysSettings'; Name = 'ASLR'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '34.3 9058'; Description = 'System DEP'' setting for ''Application Opt-Out'''; RegistryPath = 'HKLM:\Software\Policies\Microsoft\EMET\SysSettings'; Name = 'DEP'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '34.4 9059'; Description = 'System SEHOP setting for Application Opt-Out'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\EMET\SysSettings'; Name = 'SEHOP'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '34.9 1458'; Description = 'MSS: (SafeDLLSearchMode) Enable Safe DLL search mode (recommended)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Session Manager'; Name = 'SafeDllSearchMode'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '35.2 1154'; Description = 'Network access: Do not allow storage of credentials or .NET passports for network authentication'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'; Name = 'DisableDomainCreds'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '35.3 1155'; Description = 'Interactive Logon: Number of Previous Logons to Cache (in case domain controller is not available)'; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon'; Name = 'CachedLogonCount'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '35.4 2585'; Description = 'Status of the ''Network access: Do not allow storage of passwords and credentials for'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'; Name = 'DisableDomainCreds'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '35.5 4119'; Description = 'Status of the ''Allow indexing of encrypted files'' Group Policy setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'; Name = 'AllowIndexingEncryptedStoresOrItems'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '35.8 8462'; Description = 'Encrypted File System Service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\EFS'; Name = 'Start'; Value = 3; Enabled = $false }
    [PSCustomObject]@{ Control = '35.10 3875'; Description = 'Do not allow drive redirection'' setting (Terminal Services)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fDisableCdm'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '35.11 3921'; Description = 'Turn off the ''Publish to Web'' task for files and folders'' group policy'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NOPublishingWizard'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '35.26 3907'; Description = 'Status of the ''Windows Messenger Customer Experience Improvement Program'' policy -- 1 = Disabled, 2 = Enabled (2 expected)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Messenger\Client'; Name = 'CEIP'; Value = 2; Enabled = $false }
    [PSCustomObject]@{ Control = '35.27 3908'; Description = 'Status of the ''Turn off Search Companion content file updates'' service'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\SearchCompanion'; Name = 'DisableContentFileUpdates'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '37.6 3919'; Description = 'Turn off printing over HTTP'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableHTTPPrinting'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '37.7 4007'; Description = 'Windows Extensible Authentication Protocol'' (EAP) service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\EapHost'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '37.8 9008'; Description = 'Status of the ''Do not display network selection UI'' setting'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\System'; Name = 'DontDisplayNetworkSelectionUI'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '37.13 1185'; Description = 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'; Name = 'Enabled'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '37.14 1388'; Description = 'Status of the ''Network Security: LDAP client signing requirements'' setting'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LDAP'; Name = 'LDAPClientIntegrity'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '37.21 1370'; Description = 'Domain member: Digitally encrypt or sign secure channel data (always)'''; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireSignOrSeal'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '37.22 1371'; Description = 'Domain member: Digitally encrypt secure channel data (when possible)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SealSecureChannel'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '37.23 1372'; Description = 'Domain member: Digitally sign secure channel data (when possible)'' setting'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SignSecureChannel'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '37.24 1375'; Description = 'Domain member: Require strong (Windows 2000 or later) session key'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireStrongKey'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '37.25 1379'; Description = 'Microsoft network client: Digitally Sign Communications (if server agrees)'''; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'EnableSecuritySignature'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '37.26 1381'; Description = 'Microsoft network server: Digitally Sign Communications (if Client agrees)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'EnableSecuritySignature'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '37.27 1389'; Description = '''Network Security: Minimum session security for NTLM SSP based (including secure RPC) clients'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'ntlmminclientsec'; Value = 536870912; Enabled = $true }
    [PSCustomObject]@{ Control = '37.28 1390'; Description = 'Network Security: Minimum session security for NTLM SSP based (including secure RPC) servers'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'ntlmminserversec'; Value = 536870912; Enabled = $true }
    [PSCustomObject]@{ Control = '37.29 1959'; Description = '''Cryptographic Services'' service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\CryptSvc'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '37.30 2635'; Description = 'Set Client Connection Encryption Level'' setting (Terminal Services)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'MinEncryptionLevel'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '37.31 8231'; Description = 'Configure ''Network Security:Configure encryption types allowed for Kerberos'' -- 16 = AES_256_HMAC_SHA1, 8 = AES_128_HMAC_SHA1, Future Encryption Types = 2147483616, 24 = AES_128_HMAC_SHA1 and AES_256_HMAC_SHA1,'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos'; Name = 'SupportedEncryptionTypes'; Value = 2147483640; Enabled = $false }
    [PSCustomObject]@{ Control = '37.32 8252'; Description = 'Allow unencrypted traffic'' setting (WinRM service)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowUnencryptedTraffic'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '37.33 8253'; Description = 'Allow unencrypted traffic'' setting (WinRM client)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowUnencryptedTraffic'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '37.34 1149'; Description = 'Microsoft network client: Digitally sign communications (always)'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '37.35 1189'; Description = 'Status of the ''Microsoft network server: Digitally sign communication (always)'''; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\lanmanserver\Parameters'; Name = 'RequireSecuritySignature'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '38.24 1436'; Description = 'System cryptography: Force strong key protection for user keys stored on the computer -- 0 = User input is not required when new keys are stored and used 1 = User input is prompted when the first key is first used 2 = User must enter a password each time they use a key key not found all options will pass NIST'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Cryptography'; Name = 'ForceKeyProtection'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '40.2 3737'; Description = 'Status of the ''Windows Time'' service -- Should be set to Automatic'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\W32Time'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '40.4 5264'; Description = 'Microsoft network server: Server SPN target name validation level'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'; Name = 'SMBServerNameHardeningLevel'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '40.5 4056'; Description = 'Windows Net.Tcp Port Sharing'' service -- All Start Values pass NIST'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\NetTcpPortSharing'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '41.16 1597'; Description = 'DCOM: Machine Access Restrictions in Security Descriptor Definition'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\DCOM'; Name = 'MachineAccessRestriction'; Value = $null; Enabled = $false }
    [PSCustomObject]@{ Control = '41.17 1598'; Description = 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax -- Blank or key not found are acceptable'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\DCOM'; Name = 'MachineLaunchRestriction'; Value = $null; Enabled = $false }
    [PSCustomObject]@{ Control = '41.31 2582'; Description = 'User Account Control: Detect application installations and prompt for elevation -- all options will pass. Disabled/Enabled/Notset/not found'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableInstallerDetection'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '41.32 2583'; Description = 'User Account Control: Run all administrators in Admin Approval Mode'' -- All values pass (Enabled or Disabled)'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '41.33 2584'; Description = 'User Account Control: Only elevate UIAccess applications that are installed in secure locations -- All values pass'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableSecureUIAPaths'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '41.34 2587'; Description = 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; Value = 5; Enabled = $false }
    [PSCustomObject]@{ Control = '41.37 3940'; Description = 'User Account Control: Virtualize file and registry write failures to per-user -- Enabled or Disabled Passes'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableVirtualization'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '41.39 1361'; Description = 'Prevent local guests group from accessing security log'''; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Eventlog\Security'; Name = 'RestrictGuestAccess'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '41.75 1162'; Description = 'Devices: Restrict floppy access to locally logged-on user only'' -- Doesnt need to be set (1/2/not set or found)'; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon'; Name = 'Allocatefloppies'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '41.76 1163'; Description = 'Prevent users from installing printer drivers'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'; Name = 'addprinterdrivers'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '41.77 1176'; Description = 'Devices: Restrict CD-ROM Access to Locally Logged-On User Only'''; RegistryPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon'; Name = 'AllocateCDRoms'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '41.81 5267'; Description = 'Network security: Allow PKU2U authentication requests to this computer to use online ID''s'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa\pku2u'; Name = 'AllowOnlineID'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '41.251 3993'; Description = 'Smartcard Certificate Propagation -- All values are acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\CertPropSvc'; Name = 'Start'; Value = 3; Enabled = $false }
    [PSCustomObject]@{ Control = '41.255 8198'; Description = 'Windows Installer: Set Always install with elevated privileges'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '42.1 3876'; Description = 'Do not allow passwords to be saved'' policy setting (Terminal Services)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'DisablePasswordSaving'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '42.9 1430'; Description = 'Status of the ''Terminal Services'' service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\TermService'; Name = 'Start'; Value = 4; Enabled = $true }
    [PSCustomObject]@{ Control = '42.11 3892'; Description = '[Netmeeting] ''Disable Remote Desktop Sharing'' -- Enabled or Disabled'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Conferencing'; Name = 'NoRDS'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '42.12 4085'; Description = 'Terminal Services Gateway Service -- All Value are acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\TSGateway'; Name = 'Start'; Value = 2; Enabled = $false }
    [PSCustomObject]@{ Control = '42.14 9024'; Description = 'Apply UAC restrictions to local accounts on network logons'''; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LocalAccountTokenFilterPolicy'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '42.26 3793'; Description = 'Special Administration Console Helper'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\sacsvr'; Name = 'Start'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '42.27 3988'; Description = 'Windows Remote Management Service'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\WinRM'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '42.28 4035'; Description = 'Remote Desktop Services UserMode Port Redirector'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\UmRdpService'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '42.31 1510'; Description = 'Routing and Remote Access'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\RemoteAccess'; Name = 'Start'; Value = 2; Enabled = $true }
    [PSCustomObject]@{ Control = '43.16 1484'; Description = 'Telephony'' service -- all values are acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\TapiSrv'; Name = 'Start'; Value = $null; Enabled = $false }
    [PSCustomObject]@{ Control = '43.17 1965'; Description = 'Human Interface Device Access'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\HidServ'; Name = 'Start'; Value = 3; Enabled = $false }
    [PSCustomObject]@{ Control = '44.17 8143'; Description = 'Security Options ''Interactive logon: Machine account lockout threshold -- Greater than or equal to 0'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'MaxDevicePasswordFailedAttempts'; Value = 3; Enabled = $true }
    [PSCustomObject]@{ Control = '44.18 8145'; Description = 'Security Options ''Interactive logon: Machine inactivity limit''(Seconds) -- Greater than or equal to 0'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'InactivityTimeoutSecs'; Value = 30; Enabled = $true }
    [PSCustomObject]@{ Control = '44.28 9025'; Description = '''WDigest Authentication'''; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '44.40 8248'; Description = 'Disallow Digest authentication'' setting (WinRM client) -- Enabled or Disabled (Enabled is more secure)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowDigest'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '44.41 8249'; Description = 'Allow Basic authentication'' setting (WinRM client) -- Enabled or Disabled Pass'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowBasic'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '44.42 8250'; Description = 'Status of the ''Allow Basic authentication'' setting (WinRM service)'; RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowBasic'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '44.47 1376'; Description = 'Interactive Logon: Do not require CTRL+ALT+DEL'; RegistryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'DisableCAD'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '44.56 1164'; Description = 'Network Security: Do not store LAN Manager password hash value on next password change'; RegistryPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash'; Value = 1; Enabled = $true }
    [PSCustomObject]@{ Control = '44.57 1380'; Description = 'Microsoft network client: Send Unencrypted Password to Connect to Third-Party SMB Server'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'EnablePlainTextPassword'; Value = 0; Enabled = $true }
    [PSCustomObject]@{ Control = '44.80 1374'; Description = 'Domain member: Maximum machine account password age'' -- Greater than or equal to 0'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'MaximumPasswordAge'; Value = 90; Enabled = $false }
    [PSCustomObject]@{ Control = '44.87 1200'; Description = 'Status of the ''Domain Controller: Refuse machine account password changes'''; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RefusePasswordChange'; Value = 1; Enabled = $false }
    [PSCustomObject]@{ Control = '44.89 1373'; Description = 'Status of the ''Domain member: Disable machine account password changes'' -- Enabled or Disabled are acceptable'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'DisablePasswordChange'; Value = 0; Enabled = $false }
    [PSCustomObject]@{ Control = 'Additional'; Description = 'AutoShareWKS -- Lanman Default administrative shares (workstation); kept disabled/enabled alongside AutoShareServer (22.52) in the original script'; RegistryPath = 'HKLM:\System\CurrentControlSet\Services\Lanmanserver\Parameters'; Name = 'AutoShareWKS'; Value = 0; Enabled = $true }
)
#endregion

#region Apply controls
$toApply = @($controls | Where-Object { $_.Enabled })
if ($Control) {
    $toApply = @($toApply | Where-Object { $_.Control -in $Control })
}

$groups = @($toApply | Group-Object -Property RegistryPath, Name)

$results = @(foreach ($g in $groups) {
    $first = $g.Group[0]
    $controlIds = $g.Group.Control -join ', '
    $distinctValues = $g.Group.Value | Select-Object -Unique
    if ($distinctValues.Count -gt 1) {
        Write-Warning ("Controls {0} disagree on the value for {1}\{2}; using '{3}'." -f $controlIds, $first.RegistryPath, $first.Name, $first.Value)
    }

    Write-Verbose ("[{0}] {1}" -f $controlIds, $first.Description)
    $status = 'Applied'
    $errorMessage = $null
    try {
        $wasWritten = Set-HipaaControl -RegistryPath $first.RegistryPath -Name $first.Name -Value $first.Value
        if (-not $wasWritten) { $status = 'WhatIf' }
    }
    catch {
        $status = 'Failed'
        $errorMessage = $_.Exception.Message
        Write-Warning ("Controls {0} ({1}\{2}) failed: {3}" -f $controlIds, $first.RegistryPath, $first.Name, $errorMessage)
    }
    [PSCustomObject]@{
        Controls = $controlIds
        RegistryPath = $first.RegistryPath
        Name = $first.Name
        Value = $first.Value
        Status = $status
        Error = $errorMessage
    }
})

$applied = @($results | Where-Object Status -eq 'Applied').Count
$whatIf = @($results | Where-Object Status -eq 'WhatIf').Count
$failed = @($results | Where-Object Status -eq 'Failed').Count
$notApplied = $controls.Count - $toApply.Count
$notAppliedLabel = if ($Control) { 'Skipped(disabled or not matching -Control)' } else { 'Skipped(disabled)' }
Write-Host ("Done. Applied: {0}  Previewed(-WhatIf): {1}  Failed: {2}  {3}: {4}  (deduped {5} control(s) sharing a registry value with another control)" -f $applied, $whatIf, $failed, $notAppliedLabel, $notApplied, ($toApply.Count - $groups.Count))

if ($LogPath) {
    if ($PSCmdlet.ShouldProcess($LogPath, 'Write results log (CSV)')) {
        $results | Export-Csv -LiteralPath $LogPath -NoTypeInformation -Encoding UTF8
        Write-Host "Results written to $LogPath"
    }
}

$results

if ($failed -gt 0) {
    exit 1
}
#endregion
