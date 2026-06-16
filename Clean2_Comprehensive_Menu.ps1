#requires -version 5.1
<#
.SYNOPSIS
    Comprehensive Windows 10/11 Pro maintenance cleanup script with verbose console status output.

.DESCRIPTION
    This version preserves the original Clean2.ps1 behavior by default:
      - Stops Windows Update / servicing services.
      - Clears temp locations, SoftwareDistribution, CBS logs, Prefetch, browser caches, recycle bins.
      - Deletes system restore points.
      - Runs classic Disk Cleanup using the configured sagerun profile.
      - Clears IIS logs and Windows Event Logs.
      - Removes C:\Intel, C:\Config.Msi, and C:\PerfLogs.
      - Optimizes disks.
      - Restarts services.
      - Reports free space before / after.

    Additions:
      - Better admin / OS / domain context status output.
      - More cache locations including Edge, Chrome profiles, Brave, Firefox, WER, crash dumps,
        Delivery Optimization, Teams cache, thumbnail/icon caches.
      - Optional event log backup before clearing.
      - DISM component store analysis and cleanup.
      - Optional DISM health repair, SFC, volume scan, Defender update / quick scan.
      - Optional interactive menu for selecting command parameters before cleanup starts.
      - Completion status message posted to user desktops by default.
      - Completion event in the Application log when possible.

.NOTES
    Author: Mike Izzo 
    Target: Windows 10 Pro and Windows 11 Pro, including domain-joined endpoints.
    PowerShell: Windows PowerShell 5.1+

    This is intentionally aggressive because the original script is intentionally aggressive.
    Defaults do not remove any original functionality. Use parameters only to add optional checks.

.EXAMPLES
    .\Clean2_Comprehensive_NoFunctionalityRemoved.ps1
    Runs the original destructive cleanup behavior plus added cache cleanup, DISM component cleanup,
    desktop completion notice, and richer status output.

    .\Clean2_Comprehensive_NoFunctionalityRemoved.ps1 -BackupEventLogsBeforeClear $true
    Exports event logs to C:\Cleanup-EventLogBackup before clearing them.

    .\Clean2_Comprehensive_NoFunctionalityRemoved.ps1 -RunImageHealthCheck $true -RunSfcScan $true -RunVolumeScan $true
    Adds DISM /RestoreHealth, SFC, and Repair-Volume scan.

    .\Clean2_Comprehensive_NoFunctionalityRemoved.ps1 -CompletionNoticeMode Both
    Writes a desktop text notice and attempts an interactive popup when the script is running
    in an interactive user session.

    .\Clean2_Comprehensive_NoFunctionalityRemoved.ps1 -InteractiveMenu
    Presents an interactive menu for setting optional command parameters before cleanup begins.

    .\Clean2_Comprehensive_NoFunctionalityRemoved.ps1 -NoInteractiveMenu
    Suppresses the automatic menu when no parameters are supplied in an interactive session.
#>

[CmdletBinding()]
param(
    [ValidateSet('None','DesktopFile','Popup','Both')]
    [string]$CompletionNoticeMode = 'DesktopFile',

    [ValidateSet('AllProfiles','LoadedProfiles','CurrentUser')]
    [string]$DesktopNoticeScope = 'AllProfiles',

    [ValidateRange(1,9999)]
    [int]$CleanMgrProfile = 13,

    [bool]$RunDismAnalyzeComponentStore = $true,
    [bool]$RunDismComponentCleanup = $true,
    [bool]$ResetComponentBase = $false,

    [bool]$RunImageHealthCheck = $false,
    [bool]$RunSfcScan = $false,
    [bool]$RunVolumeScan = $false,

    [bool]$UpdateDefenderSignatures = $false,
    [bool]$RunDefenderQuickScan = $false,

    [bool]$BackupEventLogsBeforeClear = $false,
    [string]$EventLogBackupPath = 'C:\Cleanup-EventLogBackup',

    [string]$TranscriptPath = '',

    [switch]$InteractiveMenu,
    [switch]$NoInteractiveMenu
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'Continue'

$script:InitialBoundParameters = @{}
foreach ($key in $PSBoundParameters.Keys) {
    $script:InitialBoundParameters[$key] = $PSBoundParameters[$key]
}

$script:StartedAt = Get-Date
$script:CompletedAt = $null
$script:TranscriptStarted = $false
$script:TranscriptPath = $TranscriptPath
$script:FreespaceBefore = $null
$script:FreespaceAfter = $null
$script:ServicesSeenBefore = @{}
$script:Warnings = New-Object System.Collections.Generic.List[string]
$script:StepResults = New-Object System.Collections.Generic.List[object]
$script:DesktopNoticeFiles = New-Object System.Collections.Generic.List[string]

Write-Host "Starting Full System Cleanup..." -ForegroundColor Cyan

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAILED] $Message" -ForegroundColor Red
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "===============================" -ForegroundColor DarkCyan
    Write-Host " $Title" -ForegroundColor Magenta
    Write-Host "===============================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Add-RunWarning {
    param([string]$Message)
    [void]$script:Warnings.Add($Message)
    Write-Warn $Message
}

function Add-StepResult {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Message,
        [double]$Seconds
    )

    [void]$script:StepResults.Add([pscustomobject]@{
        Step    = $Name
        Status  = $Status
        Seconds = [math]::Round($Seconds, 2)
        Message = $Message
    })
}

function Invoke-Step {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$Action,
        [bool]$Critical = $false
    )

    Write-Section $Name
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        & $Action
        $stopwatch.Stop()
        Add-StepResult -Name $Name -Status 'Success' -Message '' -Seconds $stopwatch.Elapsed.TotalSeconds
        Write-Success "$Name complete in $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) second(s)."
    }
    catch {
        $stopwatch.Stop()
        $message = $_.Exception.Message
        Add-StepResult -Name $Name -Status 'Failed' -Message $message -Seconds $stopwatch.Elapsed.TotalSeconds
        Add-RunWarning "$Name failed: $message"
        if ($Critical) { throw }
    }
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-FreeSpaceGB {
    param([string]$Drive = 'C:')

    try {
        $deviceId = $Drive.TrimEnd(':').ToUpper() + ':'
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$deviceId'" -ErrorAction Stop
        if ($null -eq $disk) { return $null }
        return [math]::Round(($disk.FreeSpace / 1GB), 2)
    }
    catch {
        Add-RunWarning "Unable to read free space for ${Drive}: $($_.Exception.Message)"
        return $null
    }
}

function Start-CleanupTranscript {
    if ([string]::IsNullOrWhiteSpace($TranscriptPath)) {
        $script:TranscriptPath = "C:\Cleanup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    }
    else {
        $script:TranscriptPath = $TranscriptPath
    }

    try {
        $parent = Split-Path -Path $script:TranscriptPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -Path $parent -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        }

        Start-Transcript -Path $script:TranscriptPath -Force | Out-Null
        $script:TranscriptStarted = $true
        Write-Success "Transcript started: $script:TranscriptPath"
    }
    catch {
        Add-RunWarning "Unable to start transcript at $script:TranscriptPath. $($_.Exception.Message)"
    }
}

function Stop-CleanupTranscript {
    if ($script:TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
            $script:TranscriptStarted = $false
        }
        catch {
            Write-Warn "Unable to stop transcript cleanly: $($_.Exception.Message)"
        }
    }
}

function Invoke-ConsoleCommand {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Label
    )

    if (-not (Get-Command $FilePath -ErrorAction SilentlyContinue)) {
        Add-RunWarning "$Label skipped because $FilePath was not found."
        return 127
    }

    Write-Info "Running: $FilePath $($Arguments -join ' ')"
    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 }

    if ($exitCode -eq 0) {
        Write-Success "$Label exited with code 0."
    }
    else {
        Add-RunWarning "$Label exited with code $exitCode. Review console output and transcript."
    }

    return [int]$exitCode
}

function Write-RunContext {
    Write-Section "Run Context"

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

        Write-Info "Computer: $env:COMPUTERNAME"
        Write-Info "Manufacturer / Model: $($cs.Manufacturer) / $($cs.Model)"
        Write-Info "Serial Number: $($bios.SerialNumber)"
        Write-Info "OS: $($os.Caption)"
        Write-Info "Version / Build: $($os.Version) / $($os.BuildNumber)"
        Write-Info "Install Date: $($os.InstallDate)"
        Write-Info "Last Boot: $($os.LastBootUpTime)"
        Write-Info "Domain Joined: $($cs.PartOfDomain)"
        Write-Info "Domain or Workgroup: $($cs.Domain)"
        Write-Info "Run Account: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        Write-Info "PowerShell Version: $($PSVersionTable.PSVersion)"
        Write-Info "64-bit Process: $([Environment]::Is64BitProcess)"
        Write-Info "Completion Notice Mode: $CompletionNoticeMode"
        Write-Info "Desktop Notice Scope: $DesktopNoticeScope"
        Write-Info "CleanMgr Profile: $CleanMgrProfile"
        Write-Info "DISM Analyze Component Store: $RunDismAnalyzeComponentStore"
        Write-Info "DISM Component Cleanup: $RunDismComponentCleanup"
        Write-Info "Reset Component Base: $ResetComponentBase"
        Write-Info "DISM Image Health Repair: $RunImageHealthCheck"
        Write-Info "SFC Scan: $RunSfcScan"
        Write-Info "Volume Scan: $RunVolumeScan"
        Write-Info "Defender Signature Update: $UpdateDefenderSignatures"
        Write-Info "Defender Quick Scan: $RunDefenderQuickScan"
        Write-Info "Backup Event Logs Before Clear: $BackupEventLogsBeforeClear"

        if (-not [Environment]::Is64BitProcess) {
            Add-RunWarning "This script is running in a 32-bit PowerShell host. Some system paths may be redirected. Use 64-bit Windows PowerShell for fleet deployment."
        }
    }
    catch {
        Add-RunWarning "Unable to read full run context: $($_.Exception.Message)"
    }
}

function Get-PendingRebootReasons {
    $reasons = New-Object System.Collections.Generic.List[string]

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        [void]$reasons.Add('Component Based Servicing reboot pending')
    }

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        [void]$reasons.Add('Windows Update reboot required')
    }

    try {
        $sessionManager = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($sessionManager.PendingFileRenameOperations) {
            [void]$reasons.Add('Pending file rename operations')
        }
    }
    catch { }

    try {
        $updateExeVolatile = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Updates' -Name UpdateExeVolatile -ErrorAction SilentlyContinue
        if ($updateExeVolatile.UpdateExeVolatile) {
            [void]$reasons.Add('UpdateExeVolatile is set')
        }
    }
    catch { }

    return $reasons
}

function Write-PendingRebootStatus {
    Write-Section "Pending Reboot Status"
    $reasons = @(Get-PendingRebootReasons)

    if ($reasons.Count -eq 0) {
        Write-Success "No common pending reboot markers found."
    }
    else {
        foreach ($reason in $reasons) {
            Write-Warn $reason
        }
    }
}

function Write-DiskSnapshot {
    param([string]$Title)

    Write-Section "Disk Snapshot - $Title"

    try {
        $disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop | Sort-Object DeviceID)
        foreach ($disk in $disks) {
            $sizeGb = if ($disk.Size) { [math]::Round($disk.Size / 1GB, 2) } else { 0 }
            $freeGb = if ($disk.FreeSpace) { [math]::Round($disk.FreeSpace / 1GB, 2) } else { 0 }
            $freePct = if ($disk.Size) { [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2) } else { 0 }
            Write-Host ("{0}  Label: {1}  Total: {2} GB  Free: {3} GB  FreePct: {4}%" -f $disk.DeviceID, $disk.VolumeName, $sizeGb, $freeGb, $freePct) -ForegroundColor Yellow
        }
    }
    catch {
        Add-RunWarning "Unable to read disk snapshot: $($_.Exception.Message)"
    }
}

function Stop-MaintenanceServices {
    $services = @('wuauserv','TrustedInstaller','bits','cryptsvc','dosvc','msiserver')

    foreach ($serviceName in $services) {
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            Write-Info "Service not found: $serviceName"
            continue
        }

        $script:ServicesSeenBefore[$serviceName] = $svc.Status.ToString()
        Write-Info "Service $serviceName current status: $($svc.Status)"

        if ($svc.Status -ne 'Stopped') {
            Write-Warn "Stopping service: $serviceName"
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 750
            $after = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($after) { Write-Info "Service $serviceName status after stop attempt: $($after.Status)" }
        }
    }

    Write-Success "Stopped update services."
}

function Start-MaintenanceServices {
    $services = @('wuauserv','TrustedInstaller','bits','cryptsvc','dosvc','msiserver')
    $alwaysAttempt = @('wuauserv','TrustedInstaller')

    foreach ($serviceName in $services) {
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            Write-Info "Service not found: $serviceName"
            continue
        }

        if ($svc.StartType -eq 'Disabled') {
            Write-Warn "Skipping disabled service: $serviceName"
            continue
        }

        $wasRunning = ($script:ServicesSeenBefore.ContainsKey($serviceName) -and $script:ServicesSeenBefore[$serviceName] -eq 'Running')
        $shouldStart = ($alwaysAttempt -contains $serviceName) -or $wasRunning

        if ($shouldStart) {
            Write-Warn "Starting service: $serviceName"
            Start-Service -Name $serviceName -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            $after = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($after) { Write-Info "Service $serviceName status after start attempt: $($after.Status)" }
        }
        else {
            Write-Info "Leaving service $serviceName stopped because it was not running before cleanup."
        }
    }

    Write-Success "Services restarted."
}

function Remove-PathItems {
    param(
        [Parameter(Mandatory=$true)][string[]]$Paths,
        [string]$Label = 'Cleanup'
    )

    foreach ($path in $Paths) {
        Write-Warn "Clearing: $path"
        try {
            $matches = @(Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue)
            if ($matches.Count -eq 0 -and -not (Test-Path -Path $path -ErrorAction SilentlyContinue)) {
                Write-Info "No matching items found for: $path"
                continue
            }

            Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue
            Write-Success "$Label processed: $path"
        }
        catch {
            Add-RunWarning "$Label failed for ${path}: $($_.Exception.Message)"
        }
    }
}

function Cleanup-SystemTempAndCaches {
    $paths = @(
        "$env:windir\Temp\*",
        'C:\Windows\Temp\*',
        'C:\Users\*\AppData\Local\Temp\*',
        "$env:windir\SoftwareDistribution\*",
        "$env:windir\Logs\CBS\*",
        "$env:windir\Prefetch\*",
        "$env:ProgramData\Microsoft\Windows\WER\ReportArchive\*",
        "$env:ProgramData\Microsoft\Windows\WER\ReportQueue\*",
        "$env:ProgramData\Microsoft\Windows\WER\Temp\*",
        "$env:ProgramData\Microsoft\Windows\DeliveryOptimization\Cache\*",
        "$env:windir\LiveKernelReports\*",
        "$env:windir\Minidump\*",
        "$env:windir\memory.dmp"
    )

    Remove-PathItems -Paths $paths -Label 'Temp and cache cleanup'

    if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
        Write-Warn "Clearing Delivery Optimization cache using native cmdlet."
        Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Info "Delete-DeliveryOptimizationCache cmdlet not available; folder cleanup was attempted instead."
    }

    Write-Success "Temp locations cleared."
}

function Get-LocalUserProfiles {
    $profiles = @()

    try {
        $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop |
            Where-Object {
                $_.LocalPath -and
                -not $_.Special -and
                $_.LocalPath -like 'C:\Users\*' -and
                (Test-Path -LiteralPath $_.LocalPath)
            })
    }
    catch {
        Add-RunWarning "CIM user profile enumeration failed; falling back to C:\Users. $($_.Exception.Message)"
    }

    if ($profiles.Count -eq 0 -and (Test-Path -LiteralPath 'C:\Users')) {
        $profiles = @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Default','Default User','Public','All Users','defaultuser0') } |
            ForEach-Object {
                [pscustomobject]@{
                    LocalPath = $_.FullName
                    SID       = $null
                    Loaded    = $false
                    Special   = $false
                }
            })
    }

    return $profiles | Sort-Object LocalPath -Unique
}

function Cleanup-BrowserCaches {
    $profiles = @(Get-LocalUserProfiles)

    $relativePatterns = @(
        'AppData\Local\Google\Chrome\User Data\Default\Cache\*',
        'AppData\Local\Google\Chrome\User Data\*\Cache\*',
        'AppData\Local\Google\Chrome\User Data\*\Code Cache\*',
        'AppData\Local\Google\Chrome\User Data\*\GPUCache\*',
        'AppData\Local\Microsoft\Edge\User Data\*\Cache\*',
        'AppData\Local\Microsoft\Edge\User Data\*\Code Cache\*',
        'AppData\Local\Microsoft\Edge\User Data\*\GPUCache\*',
        'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Cache\*',
        'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Code Cache\*',
        'AppData\Local\Mozilla\Firefox\Profiles\*.default\cache2\*',
        'AppData\Local\Mozilla\Firefox\Profiles\*\cache2\*',
        'AppData\Local\Mozilla\Firefox\Profiles\*\startupCache\*',
        'AppData\Local\Microsoft\Windows\INetCache\*',
        'AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db',
        'AppData\Local\Microsoft\Windows\Explorer\iconcache_*.db'
    )

    foreach ($profile in $profiles) {
        Write-Info "Processing browser caches for profile: $($profile.LocalPath)"
        foreach ($relativePattern in $relativePatterns) {
            $target = Join-Path -Path $profile.LocalPath -ChildPath $relativePattern
            Remove-PathItems -Paths @($target) -Label 'Browser cache cleanup'
        }
    }

    Write-Success "Browser caches cleared."
}

function Cleanup-UserApplicationCaches {
    $profiles = @(Get-LocalUserProfiles)

    $relativePatterns = @(
        'AppData\Local\CrashDumps\*',
        'AppData\Local\Microsoft\Windows\WER\ReportArchive\*',
        'AppData\Local\Microsoft\Windows\WER\ReportQueue\*',
        'AppData\Roaming\Microsoft\Teams\Cache\*',
        'AppData\Roaming\Microsoft\Teams\Code Cache\*',
        'AppData\Roaming\Microsoft\Teams\GPUCache\*',
        'AppData\Roaming\Microsoft\Teams\tmp\*',
        'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Cache\*',
        'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Code Cache\*',
        'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\GPUCache\*'
    )

    foreach ($profile in $profiles) {
        Write-Info "Processing user application caches for profile: $($profile.LocalPath)"
        foreach ($relativePattern in $relativePatterns) {
            $target = Join-Path -Path $profile.LocalPath -ChildPath $relativePattern
            Remove-PathItems -Paths @($target) -Label 'User application cache cleanup'
        }
    }

    Write-Success "User application caches cleared."
}

function Clean-COMRecycleBin {
    Write-Info "Clearing recycle bins using Shell.Application COM object."

    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(0xA)
        if ($null -ne $recycleBin) {
            $recycleBin.Items() | ForEach-Object {
                Write-Warn "Removing recycle bin item: $($_.Path)"
                Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Success "Recycle bin cleared."
    }
    catch {
        Add-RunWarning "COM recycle bin cleanup failed: $($_.Exception.Message)"
    }

    if (Get-Command Clear-RecycleBin -ErrorAction SilentlyContinue) {
        Write-Info "Running Clear-RecycleBin fallback."
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    }
}

function Delete-SystemRestorePoints {
    $typeName = 'SystemRestore.DeleteRestorePoint'

    try {
        if (-not ([System.Management.Automation.PSTypeName]$typeName).Type) {
            Add-Type -MemberDefinition @"
        [DllImport("Srclient.dll")]
        public static extern int SRRemoveRestorePoint(int index);
"@ -Name DeleteRestorePoint -Namespace SystemRestore -PassThru | Out-Null
        }

        $restorePoints = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
        if ($restorePoints.Count -eq 0) {
            Write-Info "No system restore points found or System Restore is disabled."
            return
        }

        foreach ($restorePoint in $restorePoints) {
            Write-Warn "Deleting restore point: $($restorePoint.Description) | Sequence: $($restorePoint.SequenceNumber)"
            [void][SystemRestore.DeleteRestorePoint]::SRRemoveRestorePoint([int]$restorePoint.SequenceNumber)
        }

        Write-Success "System restore points removed."
    }
    catch {
        Add-RunWarning "System restore point deletion failed: $($_.Exception.Message)"
    }
}

function Run-CleanMgr {
    $stateFlags = 'StateFlags{0:d4}' -f $CleanMgrProfile
    $stateRun = "/sagerun:$CleanMgrProfile"
    $volumeCacheRoot = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'

    $keys = @(
        'Active Setup Temp Folders',
        'BranchCache',
        'Downloaded Program Files',
        'Internet Cache Files',
        'Offline Pages Files',
        'Old ChkDsk Files',
        'Previous Installations',
        'Memory Dump Files',
        'Recycle Bin',
        'Service Pack Cleanup',
        'Setup Log Files',
        'System error memory dump files',
        'System error minidump files',
        'Temporary Files',
        'Temporary Setup Files',
        'Thumbnail Cache',
        'Update Cleanup',
        'Upgrade Discarded Files',
        'User file versions',
        'Windows Defender',
        'Windows Error Reporting Archive Files',
        'Windows Error Reporting Queue Files',
        'Windows Error Reporting System Archive Files',
        'Windows Error Reporting System Queue Files',
        'Windows Error Reporting Temp Files',
        'Windows ESD installation files',
        'Windows Upgrade Log Files'
    )

    foreach ($key in $keys) {
        $registryPath = Join-Path -Path $volumeCacheRoot -ChildPath $key
        if (Test-Path -LiteralPath $registryPath) {
            Write-Info "Selecting CleanMgr handler: $key"
            Set-ItemProperty -Path $registryPath -Name $stateFlags -Type DWORD -Value 2 -ErrorAction SilentlyContinue
        }
        else {
            Write-Info "CleanMgr handler not present on this OS: $key"
        }
    }

    if (Get-Command CleanMgr.exe -ErrorAction SilentlyContinue) {
        Write-Info "Starting CleanMgr.exe $stateRun"
        Start-Process -FilePath CleanMgr.exe -ArgumentList $stateRun -WindowStyle Hidden -Wait
        Write-Success "CleanMgr run complete."
    }
    else {
        Add-RunWarning "CleanMgr.exe was not found. Classic Disk Cleanup skipped."
    }
}

function Invoke-DismComponentStoreMaintenance {
    if ($RunDismAnalyzeComponentStore) {
        [void](Invoke-ConsoleCommand -FilePath 'Dism.exe' -Arguments @('/Online','/Cleanup-Image','/AnalyzeComponentStore') -Label 'DISM AnalyzeComponentStore')
    }

    if ($RunDismComponentCleanup -or $ResetComponentBase) {
        $arguments = @('/Online','/Cleanup-Image','/StartComponentCleanup')
        if ($ResetComponentBase) {
            Write-Warn "ResetComponentBase is enabled. Superseded component versions will be removed and existing installed updates cannot be uninstalled afterward."
            $arguments += '/ResetBase'
        }
        [void](Invoke-ConsoleCommand -FilePath 'Dism.exe' -Arguments $arguments -Label 'DISM StartComponentCleanup')
    }
}

function Invoke-ImageHealthCheck {
    [void](Invoke-ConsoleCommand -FilePath 'Dism.exe' -Arguments @('/Online','/Cleanup-Image','/CheckHealth') -Label 'DISM CheckHealth')
    [void](Invoke-ConsoleCommand -FilePath 'Dism.exe' -Arguments @('/Online','/Cleanup-Image','/ScanHealth') -Label 'DISM ScanHealth')
    [void](Invoke-ConsoleCommand -FilePath 'Dism.exe' -Arguments @('/Online','/Cleanup-Image','/RestoreHealth') -Label 'DISM RestoreHealth')
}

function Invoke-SfcScan {
    [void](Invoke-ConsoleCommand -FilePath 'Sfc.exe' -Arguments @('/scannow') -Label 'SFC scannow')
}

function Clear-LogsAndEvents {
    Remove-PathItems -Paths @('C:\inetpub\logs\LogFiles\*') -Label 'IIS log cleanup'

    if ($BackupEventLogsBeforeClear) {
        Write-Warn "Event log backup is enabled. Exporting logs before clearing."
        if (-not (Test-Path -LiteralPath $EventLogBackupPath)) {
            New-Item -Path $EventLogBackupPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    if (-not (Get-Command wevtutil.exe -ErrorAction SilentlyContinue)) {
        Add-RunWarning "wevtutil.exe was not found. Event log clearing skipped."
        return
    }

    $logs = @(& wevtutil.exe el 2>$null)
    foreach ($log in $logs) {
        if ([string]::IsNullOrWhiteSpace($log)) { continue }

        if ($BackupEventLogsBeforeClear) {
            $safeName = ($log -replace '[\\/:*?"<>|]', '_')
            $backupFile = Join-Path -Path $EventLogBackupPath -ChildPath "$safeName.evtx"
            Write-Info "Exporting event log before clear: $log -> $backupFile"
            & wevtutil.exe epl "$log" "$backupFile" /ow:true 2>$null
            if ($LASTEXITCODE -ne 0) {
                Write-Warn "Unable to export event log: $log"
            }
        }

        Write-Warn "Clearing log: $log"
        & wevtutil.exe cl "$log" 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Unable to clear log: $log. It may be protected, disabled, or in use."
        }
    }

    Write-Success "Logs cleared."
}

function Remove-OptionalSystemFolders {
    foreach ($dir in @('C:\Intel','C:\Config.Msi','C:\PerfLogs')) {
        if (Test-Path -LiteralPath $dir) {
            Write-Warn "Removing optional system folder: $dir"
            Remove-Item $dir -Force -Recurse -ErrorAction SilentlyContinue
            Write-Success "$dir removed."
        }
        else {
            Write-Info "Optional system folder not present: $dir"
        }
    }
}

function Get-FixedVolumeLetters {
    $letters = @()

    try {
        $letters = @(Get-Volume -ErrorAction Stop |
            Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystem } |
            Select-Object -ExpandProperty DriveLetter)
    }
    catch {
        Add-RunWarning "Get-Volume failed; falling back to Win32_LogicalDisk. $($_.Exception.Message)"
        try {
            $letters = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop |
                ForEach-Object { $_.DeviceID.TrimEnd(':') })
        }
        catch {
            Add-RunWarning "Unable to enumerate fixed volumes: $($_.Exception.Message)"
        }
    }

    if ($letters -notcontains 'C') {
        $letters = @('C') + $letters
    }

    return $letters | Sort-Object -Unique
}

function Optimize-FixedVolumes {
    $letters = @(Get-FixedVolumeLetters)

    foreach ($letter in $letters) {
        Write-Warn "Optimizing drive $letter`:"
        try {
            Optimize-Volume -DriveLetter $letter -Verbose -ErrorAction Continue
        }
        catch {
            Add-RunWarning "Optimize-Volume failed for $letter`: $($_.Exception.Message)"
        }
    }
}

function Invoke-VolumeScan {
    $letters = @(Get-FixedVolumeLetters)

    foreach ($letter in $letters) {
        Write-Warn "Scanning file system on drive $letter`:"
        try {
            Repair-Volume -DriveLetter $letter -Scan -ErrorAction Continue
        }
        catch {
            Add-RunWarning "Repair-Volume scan failed for $letter`: $($_.Exception.Message)"
        }
    }
}

function Invoke-DefenderMaintenance {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Add-RunWarning "Microsoft Defender PowerShell cmdlets are not available. Defender maintenance skipped."
        return
    }

    if ($UpdateDefenderSignatures) {
        Write-Warn "Updating Microsoft Defender signatures."
        try {
            Update-MpSignature -ErrorAction Continue
            Write-Success "Defender signature update command completed."
        }
        catch {
            Add-RunWarning "Defender signature update failed: $($_.Exception.Message)"
        }
    }

    if ($RunDefenderQuickScan) {
        Write-Warn "Starting Microsoft Defender quick scan."
        try {
            Start-MpScan -ScanType QuickScan -ErrorAction Continue
            Write-Success "Defender quick scan command completed."
        }
        catch {
            Add-RunWarning "Defender quick scan failed: $($_.Exception.Message)"
        }
    }
}

function Expand-UserDesktopPath {
    param(
        [string]$RawPath,
        [string]$ProfilePath
    )

    if ([string]::IsNullOrWhiteSpace($RawPath)) { return $null }

    $expanded = $RawPath
    $expanded = $expanded.Replace('%USERPROFILE%', $ProfilePath)
    $expanded = $expanded.Replace('%userprofile%', $ProfilePath)
    $expanded = $expanded.Replace('$env:USERPROFILE', $ProfilePath)
    $expanded = [Environment]::ExpandEnvironmentVariables($expanded)

    return $expanded
}

function Get-UserDesktopTargets {
    param([ValidateSet('AllProfiles','LoadedProfiles','CurrentUser')][string]$Scope = 'AllProfiles')

    $targets = New-Object System.Collections.Generic.List[object]
    $profiles = @(Get-LocalUserProfiles)
    $currentSid = $null

    try {
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    }
    catch { }

    foreach ($profile in $profiles) {
        if ($Scope -eq 'LoadedProfiles' -and -not $profile.Loaded) { continue }

        if ($Scope -eq 'CurrentUser') {
            $isCurrent = $false
            if ($currentSid -and $profile.SID -eq $currentSid) { $isCurrent = $true }
            if ($env:USERPROFILE -and $profile.LocalPath -eq $env:USERPROFILE) { $isCurrent = $true }
            if (-not $isCurrent) { continue }
        }

        $desktop = $null

        if ($profile.SID -and $profile.Loaded) {
            $regPath = "Registry::HKEY_USERS\$($profile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            try {
                $rawDesktop = (Get-ItemProperty -Path $regPath -Name Desktop -ErrorAction SilentlyContinue).Desktop
                if ($rawDesktop) {
                    $desktop = Expand-UserDesktopPath -RawPath $rawDesktop -ProfilePath $profile.LocalPath
                }
            }
            catch { }
        }

        if ([string]::IsNullOrWhiteSpace($desktop)) {
            $desktop = Join-Path -Path $profile.LocalPath -ChildPath 'Desktop'
        }

        try {
            if (-not (Test-Path -LiteralPath $desktop)) {
                New-Item -Path $desktop -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            }

            if (Test-Path -LiteralPath $desktop) {
                [void]$targets.Add([pscustomobject]@{
                    UserProfile = $profile.LocalPath
                    Desktop     = $desktop
                    SID         = $profile.SID
                })
            }
            else {
                Write-Warn "Unable to resolve desktop path for profile: $($profile.LocalPath)"
            }
        }
        catch {
            Write-Warn "Unable to prepare desktop notice target for $($profile.LocalPath): $($_.Exception.Message)"
        }
    }

    return $targets | Sort-Object Desktop -Unique
}

function New-CompletionNoticeText {
    param([switch]$Compact)

    $completedAt = if ($script:CompletedAt) { $script:CompletedAt } else { Get-Date }
    $duration = New-TimeSpan -Start $script:StartedAt -End $completedAt
    $failedSteps = @($script:StepResults | Where-Object { $_.Status -eq 'Failed' })
    $status = if ($failedSteps.Count -gt 0) {
        'Completed with errors'
    }
    elseif ($script:Warnings.Count -gt 0) {
        'Completed with warnings'
    }
    else {
        'Completed successfully'
    }

    $reclaimed = 'Unknown'
    if ($null -ne $script:FreespaceBefore -and $null -ne $script:FreespaceAfter) {
        $reclaimed = "$([math]::Round(($script:FreespaceAfter - $script:FreespaceBefore), 2)) GB"
    }

    if ($Compact) {
        return "Automated maintenance $status on $env:COMPUTERNAME. Started: $($script:StartedAt). Completed: $completedAt. C drive reclaimed: $reclaimed. Transcript: $script:TranscriptPath"
    }

    $stepLines = ($script:StepResults | ForEach-Object {
        $line = " - {0}: {1} ({2}s)" -f $_.Step, $_.Status, $_.Seconds
        if (-not [string]::IsNullOrWhiteSpace($_.Message)) { $line += " - $($_.Message)" }
        $line
    }) -join [Environment]::NewLine

    $warningLines = if ($script:Warnings.Count -gt 0) {
        ($script:Warnings | ForEach-Object { " - $_" }) -join [Environment]::NewLine
    }
    else {
        ' - None recorded'
    }

    return @"
Automated maintenance was performed on $env:COMPUTERNAME.

Status: $status
Started: $($script:StartedAt)
Completed: $completedAt
Duration: $([math]::Round($duration.TotalMinutes, 2)) minute(s)
Run account: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
C: free before: $script:FreespaceBefore GB
C: free after: $script:FreespaceAfter GB
C: space reclaimed: $reclaimed
Transcript: $script:TranscriptPath

No action is required. This notice was placed here so users know the automated maintenance task ran.

Steps:
$stepLines

Warnings:
$warningLines
"@
}

function Write-EventLogCompletion {
    param([string]$Message)

    try {
        $source = 'AquaScience Automated Maintenance'
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            New-EventLog -LogName Application -Source $source -ErrorAction Stop
        }

        if ($Message.Length -gt 30000) {
            $Message = $Message.Substring(0, 30000)
        }

        Write-EventLog -LogName Application -Source $source -EntryType Information -EventId 2400 -Message $Message -ErrorAction Stop
        Write-Success "Completion event written to the Application log."
    }
    catch {
        Add-RunWarning "Unable to write completion event to Application log: $($_.Exception.Message)"
    }
}

function Show-CompletionPopup {
    param([string]$Message)

    if (-not [Environment]::UserInteractive) {
        Add-RunWarning "Popup notification skipped because this process is not running in an interactive desktop session. Desktop file notice is the reliable method for scheduled SYSTEM/RMM runs."
        return
    }

    try {
        $wsh = New-Object -ComObject WScript.Shell
        [void]$wsh.Popup($Message, 20, 'Automated Maintenance', 64)
        Write-Success "Interactive completion popup displayed."
    }
    catch {
        Add-RunWarning "Unable to display interactive completion popup: $($_.Exception.Message)"
    }
}

function Write-DesktopCompletionNotice {
    param([string]$Message)

    if ($CompletionNoticeMode -in @('DesktopFile','Both')) {
        $targets = @(Get-UserDesktopTargets -Scope $DesktopNoticeScope)

        if ($targets.Count -eq 0) {
            Add-RunWarning "No user desktop targets were found for completion notice scope: $DesktopNoticeScope"
        }
        else {
            foreach ($target in $targets) {
                $noticePath = Join-Path -Path $target.Desktop -ChildPath 'Automated Maintenance Performed.txt'
                try {
                    Set-Content -LiteralPath $noticePath -Value $Message -Encoding UTF8 -Force
                    [void]$script:DesktopNoticeFiles.Add($noticePath)
                    Write-Success "Posted desktop status notice: $noticePath"
                }
                catch {
                    Add-RunWarning "Unable to write desktop status notice to ${noticePath}: $($_.Exception.Message)"
                }
            }
        }
    }

    if ($CompletionNoticeMode -in @('Popup','Both')) {
        Show-CompletionPopup -Message "Automated maintenance was performed on $env:COMPUTERNAME. No action is required."
    }
}

function Complete-CleanupRun {
    $script:CompletedAt = Get-Date
    $script:FreespaceAfter = Get-FreeSpaceGB -Drive 'C:'

    $beforeText = if ($null -eq $script:FreespaceBefore) { 'Unknown' } else { "$([math]::Round($script:FreespaceBefore,2)) GB" }
    $afterText = if ($null -eq $script:FreespaceAfter) { 'Unknown' } else { "$([math]::Round($script:FreespaceAfter,2)) GB" }
    $reclaimedText = if ($null -eq $script:FreespaceBefore -or $null -eq $script:FreespaceAfter) { 'Unknown' } else { "$([math]::Round(($script:FreespaceAfter - $script:FreespaceBefore),2)) GB" }

    Write-Section "Disk Space Results"
    Write-Host "Free Space Before : $beforeText" -ForegroundColor Yellow
    Write-Host "Free Space After  : $afterText" -ForegroundColor Yellow
    Write-Host "Space Reclaimed   : $reclaimedText" -ForegroundColor Green

    Write-DiskSnapshot -Title 'After'

    Write-Section "Run Summary"
    if ($script:StepResults.Count -gt 0) {
        $script:StepResults | Format-Table -AutoSize | Out-Host
    }
    else {
        Write-Warn "No step results were recorded. That should not happen, because apparently entropy needed a hobby."
    }

    if ($script:Warnings.Count -gt 0) {
        Write-Section "Warnings"
        foreach ($warning in $script:Warnings) {
            Write-Warn $warning
        }
    }

    $compactMessage = New-CompletionNoticeText -Compact
    Write-EventLogCompletion -Message $compactMessage

    if ($CompletionNoticeMode -ne 'None') {
        Write-Section "Completion Notice"
        $noticeText = New-CompletionNoticeText
        Write-DesktopCompletionNotice -Message $noticeText
    }

    Stop-CleanupTranscript

    if ((@($script:StepResults | Where-Object { $_.Status -eq 'Failed' }).Count -gt 0) -or ($script:Warnings.Count -gt 0)) {
        Write-Host "System cleanup completed with warnings. Review transcript: $script:TranscriptPath" -ForegroundColor Yellow
    }
    else {
        Write-Host "System cleanup completed successfully." -ForegroundColor Cyan
    }
}

function Test-ShouldShowInteractiveMenu {
    if ($NoInteractiveMenu) { return $false }

    if (-not [Environment]::UserInteractive) {
        if ($InteractiveMenu) {
            Write-Warn "Interactive menu was requested, but this process is not running in an interactive user session. Continuing without menu."
        }
        return $false
    }

    if ($InteractiveMenu) { return $true }

    $nonMenuBoundParameters = @($script:InitialBoundParameters.Keys | Where-Object {
        $_ -notin @('InteractiveMenu','NoInteractiveMenu')
    })

    return ($nonMenuBoundParameters.Count -eq 0)
}

function Read-IndexedMenuValue {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string[]]$Values,
        [Parameter(Mandatory=$true)][string]$CurrentValue
    )

    Write-Host ""
    Write-Host $Title -ForegroundColor Magenta

    for ($i = 0; $i -lt $Values.Count; $i++) {
        Write-Host (" {0}. {1}" -f ($i + 1), $Values[$i]) -ForegroundColor Yellow
    }

    while ($true) {
        $raw = Read-Host "Choose 1-$($Values.Count), or press Enter to keep [$CurrentValue]"
        if ([string]::IsNullOrWhiteSpace($raw)) { return $CurrentValue }

        $selectedIndex = 0
        if ([int]::TryParse($raw, [ref]$selectedIndex) -and $selectedIndex -ge 1 -and $selectedIndex -le $Values.Count) {
            return $Values[$selectedIndex - 1]
        }

        Write-Warn "Invalid selection. Choose a number from 1 through $($Values.Count)."
    }
}

function Read-IntegerMenuValue {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][int]$CurrentValue,
        [Parameter(Mandatory=$true)][int]$Minimum,
        [Parameter(Mandatory=$true)][int]$Maximum
    )

    while ($true) {
        $raw = Read-Host "$Title [$CurrentValue]"
        if ([string]::IsNullOrWhiteSpace($raw)) { return $CurrentValue }

        $newValue = 0
        if ([int]::TryParse($raw, [ref]$newValue) -and $newValue -ge $Minimum -and $newValue -le $Maximum) {
            return $newValue
        }

        Write-Warn "Invalid value. Enter a number from $Minimum through $Maximum."
    }
}

function Read-StringMenuValue {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [AllowNull()][string]$CurrentValue,
        [string]$ClearKeyword = 'CLEAR'
    )

    $currentDisplay = if ([string]::IsNullOrWhiteSpace($CurrentValue)) { '<automatic/default>' } else { $CurrentValue }
    $raw = Read-Host "$Title [$currentDisplay] - press Enter to keep, type $ClearKeyword to clear"

    if ([string]::IsNullOrWhiteSpace($raw)) { return $CurrentValue }
    if ($raw.Trim().ToUpperInvariant() -eq $ClearKeyword.ToUpperInvariant()) { return '' }

    return $raw
}

function Toggle-MenuBooleanOption {
    param(
        [Parameter(Mandatory=$true)][string]$VariableName,
        [Parameter(Mandatory=$true)][string]$DisplayName,
        [string]$WarnWhenEnabling = ''
    )

    $currentValue = [bool](Get-Variable -Name $VariableName -Scope Script -ValueOnly)
    $newValue = -not $currentValue

    if ($newValue -and -not [string]::IsNullOrWhiteSpace($WarnWhenEnabling)) {
        Write-Warn $WarnWhenEnabling
        $confirmation = Read-Host "Type YES to enable $DisplayName"
        if ($confirmation -ne 'YES') {
            Write-Warn "$DisplayName was not changed."
            return
        }
    }

    Set-Variable -Name $VariableName -Scope Script -Value $newValue
    Write-Success "$DisplayName set to $newValue."
}

function Reset-CleanupOptionsToDefaults {
    $script:CompletionNoticeMode = 'DesktopFile'
    $script:DesktopNoticeScope = 'AllProfiles'
    $script:CleanMgrProfile = 13
    $script:RunDismAnalyzeComponentStore = $true
    $script:RunDismComponentCleanup = $true
    $script:ResetComponentBase = $false
    $script:RunImageHealthCheck = $false
    $script:RunSfcScan = $false
    $script:RunVolumeScan = $false
    $script:UpdateDefenderSignatures = $false
    $script:RunDefenderQuickScan = $false
    $script:BackupEventLogsBeforeClear = $false
    $script:EventLogBackupPath = 'C:\Cleanup-EventLogBackup'
    $script:TranscriptPath = ''

    Write-Success "Optional parameters reset to script defaults."
}

function Enable-ThoroughHealthOptions {
    $script:RunImageHealthCheck = $true
    $script:RunSfcScan = $true
    $script:RunVolumeScan = $true
    $script:UpdateDefenderSignatures = $true
    $script:RunDefenderQuickScan = $true

    Write-Success "Thorough health options enabled: DISM RestoreHealth, SFC, volume scan, Defender update, and Defender quick scan."
}

function Write-SelectedCleanupOptions {
    Write-Section "Selected Optional Parameters"

    $rows = [ordered]@{
        'CompletionNoticeMode'        = $script:CompletionNoticeMode
        'DesktopNoticeScope'          = $script:DesktopNoticeScope
        'CleanMgrProfile'             = $script:CleanMgrProfile
        'RunDismAnalyzeComponentStore'= $script:RunDismAnalyzeComponentStore
        'RunDismComponentCleanup'     = $script:RunDismComponentCleanup
        'ResetComponentBase'          = $script:ResetComponentBase
        'RunImageHealthCheck'         = $script:RunImageHealthCheck
        'RunSfcScan'                  = $script:RunSfcScan
        'RunVolumeScan'               = $script:RunVolumeScan
        'UpdateDefenderSignatures'    = $script:UpdateDefenderSignatures
        'RunDefenderQuickScan'        = $script:RunDefenderQuickScan
        'BackupEventLogsBeforeClear'  = $script:BackupEventLogsBeforeClear
        'EventLogBackupPath'          = $script:EventLogBackupPath
        'TranscriptPath'              = if ([string]::IsNullOrWhiteSpace($script:TranscriptPath)) { '<automatic>' } else { $script:TranscriptPath }
    }

    foreach ($key in $rows.Keys) {
        Write-Host ("{0,-32}: {1}" -f $key, $rows[$key]) -ForegroundColor Yellow
    }
}

function Show-CleanupOptionsMenu {
    Write-Host ""
    Write-Host "Interactive Cleanup Options Menu" -ForegroundColor Cyan
    Write-Host "Select optional command parameters before the cleanup begins." -ForegroundColor Cyan
    Write-Host "Blank entries keep the current value. Boolean entries toggle true/false." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host (" 1. CompletionNoticeMode        {0}" -f $script:CompletionNoticeMode) -ForegroundColor Yellow
    Write-Host (" 2. DesktopNoticeScope          {0}" -f $script:DesktopNoticeScope) -ForegroundColor Yellow
    Write-Host (" 3. CleanMgrProfile             {0}" -f $script:CleanMgrProfile) -ForegroundColor Yellow
    Write-Host (" 4. RunDismAnalyzeComponentStore {0}" -f $script:RunDismAnalyzeComponentStore) -ForegroundColor Yellow
    Write-Host (" 5. RunDismComponentCleanup     {0}" -f $script:RunDismComponentCleanup) -ForegroundColor Yellow
    Write-Host (" 6. ResetComponentBase          {0}" -f $script:ResetComponentBase) -ForegroundColor Yellow
    Write-Host (" 7. RunImageHealthCheck         {0}" -f $script:RunImageHealthCheck) -ForegroundColor Yellow
    Write-Host (" 8. RunSfcScan                  {0}" -f $script:RunSfcScan) -ForegroundColor Yellow
    Write-Host (" 9. RunVolumeScan               {0}" -f $script:RunVolumeScan) -ForegroundColor Yellow
    Write-Host ("10. UpdateDefenderSignatures    {0}" -f $script:UpdateDefenderSignatures) -ForegroundColor Yellow
    Write-Host ("11. RunDefenderQuickScan        {0}" -f $script:RunDefenderQuickScan) -ForegroundColor Yellow
    Write-Host ("12. BackupEventLogsBeforeClear  {0}" -f $script:BackupEventLogsBeforeClear) -ForegroundColor Yellow
    Write-Host ("13. EventLogBackupPath          {0}" -f $script:EventLogBackupPath) -ForegroundColor Yellow
    $transcriptDisplay = if ([string]::IsNullOrWhiteSpace($script:TranscriptPath)) { '<automatic>' } else { $script:TranscriptPath }
    Write-Host ("14. TranscriptPath              {0}" -f $transcriptDisplay) -ForegroundColor Yellow
    Write-Host ""
    Write-Host "T. Enable thorough health options" -ForegroundColor Green
    Write-Host "D. Reset optional parameters to defaults" -ForegroundColor Green
    Write-Host "P. Print selected options" -ForegroundColor Green
    Write-Host "R. Run cleanup with selected options" -ForegroundColor Green
    Write-Host "Q. Quit without running cleanup" -ForegroundColor Red
    Write-Host ""
}

function Invoke-CleanupOptionsMenu {
    while ($true) {
        Show-CleanupOptionsMenu
        $rawChoice = Read-Host 'Select an option'
        if ($null -eq $rawChoice) { continue }
        $choice = $rawChoice.Trim().ToUpperInvariant()

        switch ($choice) {
            '1' {
                $script:CompletionNoticeMode = Read-IndexedMenuValue -Title 'CompletionNoticeMode' -Values @('None','DesktopFile','Popup','Both') -CurrentValue $script:CompletionNoticeMode
            }
            '2' {
                $script:DesktopNoticeScope = Read-IndexedMenuValue -Title 'DesktopNoticeScope' -Values @('AllProfiles','LoadedProfiles','CurrentUser') -CurrentValue $script:DesktopNoticeScope
            }
            '3' {
                $script:CleanMgrProfile = Read-IntegerMenuValue -Title 'CleanMgrProfile' -CurrentValue $script:CleanMgrProfile -Minimum 1 -Maximum 9999
            }
            '4' { Toggle-MenuBooleanOption -VariableName 'RunDismAnalyzeComponentStore' -DisplayName 'RunDismAnalyzeComponentStore' }
            '5' { Toggle-MenuBooleanOption -VariableName 'RunDismComponentCleanup' -DisplayName 'RunDismComponentCleanup' }
            '6' {
                Toggle-MenuBooleanOption -VariableName 'ResetComponentBase' -DisplayName 'ResetComponentBase' -WarnWhenEnabling 'ResetComponentBase removes superseded component versions. Installed updates cannot be uninstalled afterward.'
            }
            '7' { Toggle-MenuBooleanOption -VariableName 'RunImageHealthCheck' -DisplayName 'RunImageHealthCheck' }
            '8' { Toggle-MenuBooleanOption -VariableName 'RunSfcScan' -DisplayName 'RunSfcScan' }
            '9' { Toggle-MenuBooleanOption -VariableName 'RunVolumeScan' -DisplayName 'RunVolumeScan' }
            '10' { Toggle-MenuBooleanOption -VariableName 'UpdateDefenderSignatures' -DisplayName 'UpdateDefenderSignatures' }
            '11' { Toggle-MenuBooleanOption -VariableName 'RunDefenderQuickScan' -DisplayName 'RunDefenderQuickScan' }
            '12' { Toggle-MenuBooleanOption -VariableName 'BackupEventLogsBeforeClear' -DisplayName 'BackupEventLogsBeforeClear' }
            '13' {
                $script:EventLogBackupPath = Read-StringMenuValue -Title 'EventLogBackupPath' -CurrentValue $script:EventLogBackupPath
            }
            '14' {
                $script:TranscriptPath = Read-StringMenuValue -Title 'TranscriptPath' -CurrentValue $script:TranscriptPath
            }
            'T' { Enable-ThoroughHealthOptions }
            'D' { Reset-CleanupOptionsToDefaults }
            'P' { Write-SelectedCleanupOptions }
            'R' {
                Write-SelectedCleanupOptions
                return
            }
            'Q' {
                Write-Warn 'Cleanup cancelled from interactive menu.'
                exit 0
            }
            default {
                Write-Warn 'Invalid menu selection.'
            }
        }
    }
}

function Cleanup-System {
    if (-not (Test-IsAdministrator)) {
        Write-Fail "This script must be run from an elevated PowerShell session."
        exit 1
    }

    $script:FreespaceBefore = Get-FreeSpaceGB -Drive 'C:'
    Start-CleanupTranscript

    Write-RunContext
    Write-DiskSnapshot -Title 'Before'
    Write-PendingRebootStatus

    try {
        Invoke-Step -Name 'Service Control' -Action { Stop-MaintenanceServices }

        Invoke-Step -Name 'Temp & Cache Cleanup' -Action { Cleanup-SystemTempAndCaches }

        Invoke-Step -Name 'Browser Cache Cleanup' -Action { Cleanup-BrowserCaches }

        Invoke-Step -Name 'User Application Cache Cleanup' -Action { Cleanup-UserApplicationCaches }

        Invoke-Step -Name 'Clearing Recycle Bins' -Action { Clean-COMRecycleBin }

        Invoke-Step -Name 'Deleting System Restore Points' -Action { Delete-SystemRestorePoints }

        Invoke-Step -Name 'Running CleanMgr (Classic Disk Cleanup)' -Action { Run-CleanMgr }

        if ($RunDismAnalyzeComponentStore -or $RunDismComponentCleanup -or $ResetComponentBase) {
            Invoke-Step -Name 'DISM Component Store Maintenance' -Action { Invoke-DismComponentStoreMaintenance }
        }

        if ($RunImageHealthCheck) {
            Invoke-Step -Name 'DISM Image Health Check and Repair' -Action { Invoke-ImageHealthCheck }
        }

        if ($RunSfcScan) {
            Invoke-Step -Name 'System File Checker Scan' -Action { Invoke-SfcScan }
        }

        Invoke-Step -Name 'Log & Event Cleanup' -Action { Clear-LogsAndEvents }

        Invoke-Step -Name 'Optional System Folders' -Action { Remove-OptionalSystemFolders }

        Invoke-Step -Name 'Defrag Disk' -Action { Optimize-FixedVolumes }

        if ($RunVolumeScan) {
            Invoke-Step -Name 'Volume File System Scan' -Action { Invoke-VolumeScan }
        }

        if ($UpdateDefenderSignatures -or $RunDefenderQuickScan) {
            Invoke-Step -Name 'Microsoft Defender Maintenance' -Action { Invoke-DefenderMaintenance }
        }
    }
    finally {
        Invoke-Step -Name 'Restarting Services' -Action { Start-MaintenanceServices }
        Complete-CleanupRun
    }
}

if (Test-ShouldShowInteractiveMenu) {
    Invoke-CleanupOptionsMenu
}

Cleanup-System
