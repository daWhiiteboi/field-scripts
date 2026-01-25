<#
.SYNOPSIS
    Comprehensive Windows security audit script for monthly security reviews.

.DESCRIPTION
    Collects and analyzes:
    - Windows Defender blocks and detections
    - Suspicious PowerShell execution patterns
    - Credential Guard/VBS configuration and failures
    - Application crash patterns
    - Additional security signals (failed logins, account changes, firewall events)
    
.PARAMETER DaysBack
    Number of days to look back in event logs (default: 30)
    
.PARAMETER TopCrashPairs
    Number of top crash patterns to report (default: 20)
    
.PARAMETER OutDir
    Output directory for audit reports (default: auto-generated in Public folder)
    
.PARAMETER IncludeExtendedAnalysis
    Enable additional security checks (slower but more comprehensive)
    
.EXAMPLE
    .\Audit-SecurityMonthly.ps1 -DaysBack 30 -IncludeExtendedAnalysis
    
.NOTES
    Requires: Administrator privileges for best coverage
    Tested: Windows 10/11
    Author: Security Operations
    Version: 2.0
#>

param(
    [int]$DaysBack = 30,
    [int]$TopCrashPairs = 20,
    [string]$OutDir = "$env:PUBLIC\SOS_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$IncludeExtendedAnalysis
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helper Functions

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    $colors = @{
        Info = 'Cyan'
        Warning = 'Yellow'
        Error = 'Red'
        Success = 'Green'
    }
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host $Message -ForegroundColor $colors[$Level]
}

function Get-WinEventsSafe {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,
        [int[]]$Id = @(),
        [datetime]$StartTime,
        [int]$MaxEvents = 0
    )
    try {
        $fh = @{ 
            LogName = $LogName
            StartTime = $StartTime 
        }
        if ($Id.Count -gt 0) { $fh.Id = $Id }
        if ($MaxEvents -gt 0) { $fh.MaxEvents = $MaxEvents }
        
        Get-WinEvent -FilterHashtable $fh -ErrorAction Stop
    }
    catch [System.Exception] {
        if ($_.Exception.Message -notmatch 'No events were found') {
            Write-AuditLog "Warning accessing $LogName : $($_.Exception.Message)" -Level Warning
        }
        @()
    }
}

function Export-AuditData {
    param(
        [Parameter(Mandatory)]
        $Data,
        [Parameter(Mandatory)]
        [string]$FileName,
        [string]$Description
    )
    
    $path = Join-Path $OutDir $FileName
    
    if ($Data -and $Data.Count -gt 0) {
        $Data | Export-Csv -NoTypeInformation -Path $path
        Write-AuditLog "$Description : $($Data.Count) entries exported" -Level Success
    }
    else {
        Write-AuditLog "$Description : No data found" -Level Info
        # Create empty file to indicate check was performed
        "# No data found for this audit period" | Out-File -FilePath $path
    }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

#region Initialization

Write-AuditLog "=== Windows Security Audit Script ===" -Level Success
Write-AuditLog "Audit Period: Last $DaysBack days"
Write-AuditLog "Output Directory: $OutDir"

if (-not (Test-IsAdmin)) {
    Write-AuditLog "WARNING: Not running as Administrator. Some logs may be inaccessible." -Level Warning
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$Start = (Get-Date).AddDays(-$DaysBack)
$auditMetadata = @{
    AuditStartTime = Get-Date
    LookbackDays = $DaysBack
    ComputerName = $env:COMPUTERNAME
    OSVersion = [System.Environment]::OSVersion.VersionString
    RunAsAdmin = Test-IsAdmin
    PSVersion = $PSVersionTable.PSVersion.ToString()
}

#endregion

#region 1. Windows Defender Analysis

Write-AuditLog "`n[1/6] Analyzing Windows Defender events..." -Level Info

$defenderEvents = Get-WinEventsSafe -LogName "Microsoft-Windows-Windows Defender/Operational" -StartTime $Start
$mpDetections = @()

try {
    $mpDetections = Get-MpThreatDetection -ErrorAction Stop
    Write-AuditLog "Retrieved $($mpDetections.Count) threat detections from Get-MpThreatDetection"
}
catch {
    Write-AuditLog "Get-MpThreatDetection not available: $($_.Exception.Message)" -Level Warning
}

# Parse operational log events
$defenderFindings = @()
$threatPatterns = '(?i)\b(threat|blocked|quarantin|remediat|detected|malware|virus|trojan|ransomware|adware|spyware)\b'

foreach ($e in $defenderEvents) {
    $msg = $e.Message
    if (-not $msg) { continue }
    
    if ($msg -match $threatPatterns) {
        $defenderFindings += [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            EventId = $e.Id
            Level = $e.LevelDisplayName
            Provider = $e.ProviderName
            ThreatHint = (($msg -split "`r?`n") | Select-Object -First 1)
            FullMessage = $msg
        }
    }
}

# Structured threat detections
$mpDetectionFindings = @()
foreach ($d in $mpDetections) {
    $mpDetectionFindings += [pscustomobject]@{
        InitialDetectionTime = $d.InitialDetectionTime
        ThreatName = $d.ThreatName
        ActionSuccess = $d.ActionSuccess
        Resources = ($d.Resources -join '; ')
        ProcessName = $d.ProcessName
        User = $d.User
        DetectionId = $d.DetectionID
        Severity = $d.SeverityID
        Category = $d.CategoryID
    }
}

Export-AuditData -Data $defenderFindings -FileName "defender_operational_findings.csv" -Description "Defender Operational Events"
Export-AuditData -Data $mpDetectionFindings -FileName "defender_mp_threat_detections.csv" -Description "Defender Threat Detections"

#endregion

#region 2. Suspicious PowerShell Execution

Write-AuditLog "`n[2/6] Analyzing PowerShell execution patterns..." -Level Info

$psOps = Get-WinEventsSafe -LogName "Microsoft-Windows-PowerShell/Operational" -StartTime $Start
$psClassic = Get-WinEventsSafe -LogName "Windows PowerShell" -StartTime $Start

# Event IDs: 4103 (Module), 4104 (Script Block), 600 (Provider), 800 (Pipeline)
$psOpsInteresting = $psOps | Where-Object { $_.Id -in 4103,4104,600,800 }

# Enhanced suspicious patterns
$suspiciousPatterns = @(
    '(?i)\b-enc(odedcommand)?\b',
    '(?i)\bfrombase64string\b',
    '(?i)\biex\b|\binvoke-expression\b',
    '(?i)\binvoke-webrequest\b|\biwr\b',
    '(?i)\binvoke-restmethod\b|\birm\b',
    '(?i)\bnew-object\s+net\.webclient\b',
    '(?i)\bdownloadstring\b|\bdownloadfile\b',
    '(?i)\bbitsadmin\b.*\btransfer\b',
    '(?i)\bcertutil\b.*\burlcache\b',
    '(?i)\badd-mppreference\b.*\bexclusion\b',
    '(?i)\bset-mppreference\b.*\bexclusion\b',
    '(?i)\bhidden\s+window',
    '(?i)\bbypass\b.*\bexecution',
    '(?i)\breflection\.assembly\b.*\bload\b',
    '(?i)\bsystem\.management\.automation\b',
    '(?i)\bamsi\b.*\bbypass\b',
    '(?i)\bmemorystream\b.*\bgzipstream\b'
)

function Select-SuspiciousPSEvents {
    param([System.Collections.Generic.IEnumerable[System.Diagnostics.Eventing.Reader.EventRecord]]$Events)
    
    $out = @()
    foreach ($e in $Events) {
        $msg = $e.Message
        if (-not $msg) { continue }
        
        $hits = @()
        foreach ($pat in $suspiciousPatterns) {
            if ($msg -match $pat) {
                $hits += $pat
            }
        }
        
        if ($hits.Count -gt 0) {
            # Extract script block content if available
            $scriptContent = ""
            if ($e.Id -eq 4104) {
                try {
                    $xml = [xml]$e.ToXml()
                    $scriptContent = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ScriptBlockText' } | Select-Object -ExpandProperty '#text' -First 1
                }
                catch { }
            }
            
            $out += [pscustomobject]@{
                TimeCreated = $e.TimeCreated
                Log = $e.LogName
                EventId = $e.Id
                Level = $e.LevelDisplayName
                HitCount = $hits.Count
                HitPatterns = ($hits -join " | ")
                Preview = (($msg -replace "`r?`n",' ') -replace '\s+',' ').Substring(0, [Math]::Min(200, $msg.Length))
                ScriptBlock = if ($scriptContent) { $scriptContent.Substring(0, [Math]::Min(500, $scriptContent.Length)) } else { "" }
                FullMessage = $msg
            }
        }
    }
    $out
}

$psSuspicious = @()
$psSuspicious += Select-SuspiciousPSEvents -Events $psOpsInteresting
$psSuspicious += Select-SuspiciousPSEvents -Events $psClassic

Export-AuditData -Data $psSuspicious -FileName "powershell_suspicious_events.csv" -Description "Suspicious PowerShell Events"

# Security 4688 process creation (if auditing enabled)
$procCreate = @()
try {
    $sec4688 = Get-WinEventsSafe -LogName "Security" -Id 4688 -StartTime $Start
    
    foreach ($e in $sec4688) {
        $x = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $x.Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }
        
        $newProc = $data["NewProcessName"]
        $cmdLine = $data["CommandLine"]
        
        if (($newProc -match '(?i)\\powershell\.exe$|\\pwsh\.exe$') -or ($cmdLine -match '(?i)\bpowershell\b|\bpwsh\b')) {
            $hit = $false
            foreach ($pat in $suspiciousPatterns) {
                if ($cmdLine -match $pat) {
                    $hit = $true
                    break
                }
            }
            
            if ($hit) {
                $procCreate += [pscustomobject]@{
                    TimeCreated = $e.TimeCreated
                    NewProcess = $newProc
                    ParentProcess = $data["ParentProcessName"]
                    SubjectUser = $data["SubjectUserName"]
                    CommandLine = $cmdLine
                }
            }
        }
    }
}
catch {
    Write-AuditLog "Security 4688 audit may not be enabled" -Level Warning
}

Export-AuditData -Data $procCreate -FileName "security_4688_suspicious_powershell.csv" -Description "Security 4688 Suspicious PowerShell"

#endregion

#region 3. Credential Guard / Device Guard Status

Write-AuditLog "`n[3/6] Checking Credential Guard / Device Guard status..." -Level Info

$cgStatus = @()
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    
    $cgStatus = [pscustomobject]@{
        TimeChecked = Get-Date
        VirtualizationBasedSecurityStatus = $dg.VirtualizationBasedSecurityStatus
        VBSStatusText = switch ($dg.VirtualizationBasedSecurityStatus) {
            0 { "Not enabled" }
            1 { "Enabled but not running" }
            2 { "Enabled and running" }
            default { "Unknown: $($dg.VirtualizationBasedSecurityStatus)" }
        }
        SecurityServicesConfigured = ($dg.SecurityServicesConfigured -join ',')
        SecurityServicesRunning = ($dg.SecurityServicesRunning -join ',')
        CodeIntegrityPolicyEnforcementStatus = $dg.CodeIntegrityPolicyEnforcementStatus
        RequiredSecurityProperties = ($dg.RequiredSecurityProperties -join ',')
        AvailableSecurityProperties = ($dg.AvailableSecurityProperties -join ',')
    }
    
    Write-AuditLog "VBS Status: $($cgStatus.VBSStatusText)"
}
catch {
    $cgStatus = [pscustomobject]@{
        TimeChecked = Get-Date
        Error = "Win32_DeviceGuard not accessible: $($_.Exception.Message)"
    }
    Write-AuditLog "Could not query Device Guard status" -Level Warning
}

$cgStatus | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 (Join-Path $OutDir "credential_guard_deviceguard_status.json")

# Device Guard / Credential Guard related events
$dgEvents = @()
$dgEvents += Get-WinEventsSafe -LogName "Microsoft-Windows-DeviceGuard/Operational" -StartTime $Start
$dgEvents += Get-WinEventsSafe -LogName "Microsoft-Windows-Kernel-Boot/Operational" -StartTime $Start
$dgEvents += Get-WinEventsSafe -LogName "System" -StartTime $Start

$dgFindings = @()
$dgPattern = '(?i)\b(device guard|credential guard|vbs|virtualization-based|lsass|lsa protection|hvci)\b'
$errorPattern = '(?i)\b(fail|error|could not|not enabled|disabled|stopped|unable)\b'

foreach ($e in $dgEvents) {
    $msg = $e.Message
    if (-not $msg) { continue }
    
    if ($msg -match $dgPattern -and $msg -match $errorPattern) {
        $dgFindings += [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            Log = $e.LogName
            EventId = $e.Id
            Level = $e.LevelDisplayName
            Provider = $e.ProviderName
            Preview = (($msg -replace "`r?`n",' ') -replace '\s+',' ').Substring(0, [Math]::Min(200, $msg.Length))
            FullMessage = $msg
        }
    }
}

Export-AuditData -Data $dgFindings -FileName "credential_guard_failure_signals.csv" -Description "Credential Guard Failure Signals"

#endregion

#region 4. Application Crashes

Write-AuditLog "`n[4/6] Analyzing application crash patterns..." -Level Info

$app = Get-WinEventsSafe -LogName "Application" -StartTime $Start
$appErr = $app | Where-Object { $_.Id -in 1000,1001,1002 } # 1000=App Error, 1001=WER, 1002=App Hang

$crashes = @()
foreach ($e in $appErr) {
    $msg = $e.Message
    if (-not $msg) { continue }
    
    $faultApp = $null
    $faultMod = $null
    $faultCode = $null
    $faultOffset = $null
    
    if ($msg -match '(?i)Faulting application name:\s*([^\r\n,]+)') {
        $faultApp = $Matches[1].Trim()
    }
    if ($msg -match '(?i)Faulting module name:\s*([^\r\n,]+)') {
        $faultMod = $Matches[1].Trim()
    }
    if ($msg -match '(?i)Exception code:\s*([^\r\n,]+)') {
        $faultCode = $Matches[1].Trim()
    }
    if ($msg -match '(?i)Fault offset:\s*([^\r\n,]+)') {
        $faultOffset = $Matches[1].Trim()
    }
    
    $crashes += [pscustomobject]@{
        TimeCreated = $e.TimeCreated
        EventId = $e.Id
        FaultingApp = $faultApp
        FaultingModule = $faultMod
        ExceptionCode = $faultCode
        FaultOffset = $faultOffset
        Preview = (($msg -replace "`r?`n",' ') -replace '\s+',' ').Substring(0, [Math]::Min(150, $msg.Length))
        FullMessage = $msg
    }
}

Export-AuditData -Data $crashes -FileName "crash_events_raw.csv" -Description "Application Crash Events"

# Top crash patterns
$topCrash = $crashes | 
    Where-Object { $_.FaultingApp -or $_.FaultingModule } | 
    Group-Object -Property FaultingApp,FaultingModule | 
    Sort-Object Count -Descending | 
    Select-Object -First $TopCrashPairs | 
    ForEach-Object {
        [pscustomobject]@{
            Count = $_.Count
            FaultingApp = $_.Group[0].FaultingApp
            FaultingModule = $_.Group[0].FaultingModule
            FirstSeen = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
            LastSeen = ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
            CommonExceptionCode = ($_.Group | Group-Object ExceptionCode | Sort-Object Count -Descending | Select-Object -First 1).Name
        }
    }

Export-AuditData -Data $topCrash -FileName "crash_top_pairs.csv" -Description "Top Crash Patterns"

#endregion

#region 5. Extended Security Analysis (Optional)

if ($IncludeExtendedAnalysis) {
    Write-AuditLog "`n[5/6] Performing extended security analysis..." -Level Info
    
    # Failed login attempts (4625)
    try {
        $failedLogins = Get-WinEventsSafe -LogName "Security" -Id 4625 -StartTime $Start
        $failedLoginSummary = @()
        
        foreach ($e in $failedLogins) {
            $x = [xml]$e.ToXml()
            $data = @{}
            foreach ($d in $x.Event.EventData.Data) {
                $data[$d.Name] = $d.'#text'
            }
            
            $failedLoginSummary += [pscustomobject]@{
                TimeCreated = $e.TimeCreated
                TargetUser = $data["TargetUserName"]
                WorkstationName = $data["WorkstationName"]
                IpAddress = $data["IpAddress"]
                LogonType = $data["LogonType"]
                FailureReason = $data["FailureReason"]
                SubStatus = $data["SubStatus"]
            }
        }
        
        Export-AuditData -Data $failedLoginSummary -FileName "security_failed_logins.csv" -Description "Failed Login Attempts"
    }
    catch {
        Write-AuditLog "Could not retrieve failed login events" -Level Warning
    }
    
    # Account changes (4720=created, 4722=enabled, 4724=password reset, 4738=changed)
    try {
        $accountChanges = Get-WinEventsSafe -LogName "Security" -Id @(4720,4722,4724,4738,4726) -StartTime $Start
        $accountSummary = @()
        
        foreach ($e in $accountChanges) {
            $x = [xml]$e.ToXml()
            $data = @{}
            foreach ($d in $x.Event.EventData.Data) {
                $data[$d.Name] = $d.'#text'
            }
            
            $accountSummary += [pscustomobject]@{
                TimeCreated = $e.TimeCreated
                EventId = $e.Id
                EventType = switch ($e.Id) {
                    4720 { "Account Created" }
                    4722 { "Account Enabled" }
                    4724 { "Password Reset" }
                    4726 { "Account Deleted" }
                    4738 { "Account Changed" }
                    default { "Other" }
                }
                TargetAccount = $data["TargetUserName"]
                SubjectAccount = $data["SubjectUserName"]
            }
        }
        
        Export-AuditData -Data $accountSummary -FileName "security_account_changes.csv" -Description "Account Changes"
    }
    catch {
        Write-AuditLog "Could not retrieve account change events" -Level Warning
    }
    
    # Firewall rule changes
    try {
        $fwEvents = Get-WinEventsSafe -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" -StartTime $Start
        $fwChanges = $fwEvents | Where-Object { $_.Id -in 2004,2005,2006,2033 } # Rule added/modified/deleted
        
        $fwSummary = @()
        foreach ($e in $fwChanges) {
            $fwSummary += [pscustomobject]@{
                TimeCreated = $e.TimeCreated
                EventId = $e.Id
                Action = switch ($e.Id) {
                    2004 { "Rule Added" }
                    2005 { "Rule Modified" }
                    2006 { "Rule Deleted" }
                    2033 { "Rule Changed" }
                    default { "Other" }
                }
                Message = $e.Message
            }
        }
        
        Export-AuditData -Data $fwSummary -FileName "firewall_rule_changes.csv" -Description "Firewall Rule Changes"
    }
    catch {
        Write-AuditLog "Could not retrieve firewall events" -Level Warning
    }
}
else {
    Write-AuditLog "`n[5/6] Extended analysis skipped (use -IncludeExtendedAnalysis to enable)" -Level Info
}

#endregion

#region 6. Generate Summary Report

Write-AuditLog "`n[6/6] Generating summary report..." -Level Info

$summary = @{
    AuditMetadata = $auditMetadata
    AuditEndTime = Get-Date
    Statistics = @{
        DefenderOperationalFindings = $defenderFindings.Count
        DefenderThreatDetections = $mpDetectionFindings.Count
        SuspiciousPowerShellEvents = $psSuspicious.Count
        SuspiciousSecurity4688 = $procCreate.Count
        CredentialGuardFailures = $dgFindings.Count
        ApplicationCrashes = $crashes.Count
        TopCrashPatterns = $topCrash.Count
    }
    HighPriorityFindings = @()
}

# Identify high-priority items
if ($mpDetectionFindings.Count -gt 0) {
    $summary.HighPriorityFindings += "Found $($mpDetectionFindings.Count) threat detections"
}
if ($psSuspicious.Count -gt 10) {
    $summary.HighPriorityFindings += "High volume of suspicious PowerShell activity ($($psSuspicious.Count) events)"
}
if ($dgFindings.Count -gt 0) {
    $summary.HighPriorityFindings += "Credential Guard/Device Guard issues detected"
}

$summary | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 (Join-Path $OutDir "audit_summary.json")

#endregion

#region Console Output

Write-Host "`n" -NoNewline
Write-AuditLog "=== AUDIT COMPLETE ===" -Level Success
Write-Host "`nOutput Folder: " -NoNewline
Write-Host $OutDir -ForegroundColor Yellow

Write-Host "`n--- Statistics ---" -ForegroundColor Cyan
Write-Host "Defender findings (Operational): " -NoNewline
Write-Host $defenderFindings.Count -ForegroundColor $(if ($defenderFindings.Count -gt 0) { 'Yellow' } else { 'Green' })

Write-Host "Defender detections (Get-MpThreatDetection): " -NoNewline
Write-Host $mpDetectionFindings.Count -ForegroundColor $(if ($mpDetectionFindings.Count -gt 0) { 'Yellow' } else { 'Green' })

Write-Host "Suspicious PowerShell events: " -NoNewline
Write-Host $psSuspicious.Count -ForegroundColor $(if ($psSuspicious.Count -gt 5) { 'Red' } elseif ($psSuspicious.Count -gt 0) { 'Yellow' } else { 'Green' })

Write-Host "Suspicious Security 4688 PowerShell: " -NoNewline
Write-Host $procCreate.Count -ForegroundColor $(if ($procCreate.Count -gt 0) { 'Yellow' } else { 'Green' })

Write-Host "Credential Guard/Device Guard failures: " -NoNewline
Write-Host $dgFindings.Count -ForegroundColor $(if ($dgFindings.Count -gt 0) { 'Yellow' } else { 'Green' })

Write-Host "Application crashes: " -NoNewline
Write-Host $crashes.Count -ForegroundColor $(if ($crashes.Count -gt 50) { 'Yellow' } else { 'White' })

Write-Host "Top crash patterns exported: " -NoNewline
Write-Host $topCrash.Count -ForegroundColor White

if ($summary.HighPriorityFindings.Count -gt 0) {
    Write-Host "`n--- High Priority Findings ---" -ForegroundColor Red
    foreach ($finding in $summary.HighPriorityFindings) {
        Write-Host "  • $finding" -ForegroundColor Yellow
    }
}

Write-Host "`nAudit duration: " -NoNewline
$duration = (Get-Date) - $auditMetadata.AuditStartTime
Write-Host "$([math]::Round($duration.TotalSeconds, 1)) seconds" -ForegroundColor White

Write-Host "`nReview the CSV files in the output directory for detailed findings.`n" -ForegroundColor Gray

#endregion
