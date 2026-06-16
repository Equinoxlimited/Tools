# SystemDiagnostics.ps1
$ReportPath = "$env:USERPROFILE\Desktop\SystemReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$SysDrive = $env:SystemDrive
Write-Host "`n===> Starting system diagnostics..." -ForegroundColor Cyan

# Initialize HTML
$html = @"
<html><head><title>System Health Report</title>
<style>
body { font-family: Consolas, monospace; background: #111; color: #ddd; padding: 20px; }
h2 { color: #6cf; }
pre { background: #222; padding: 10px; border-radius: 5px; }
</style></head><body>
<h1>Windows System Diagnostic Report</h1>
"@

Function Append-Html($title, $content) {
    $script:html += "<h2>$title</h2><pre>$content</pre>`n"
}

# OS Info
Write-Host "→ Collecting OS information..." -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
Append-Html "OS Information" "$($os.Caption) $($os.Version) $($os.BuildNumber) $($os.OSArchitecture) - $($os.CSName)"

# Uptime
$uptime = (Get-Date) - $os.LastBootUpTime
Append-Html "System Uptime" "$([math]::Round($uptime.TotalHours, 2)) hours"

# CPU & RAM Usage
Write-Host "→ Gathering CPU & RAM stats..." -ForegroundColor Yellow
$cpuLoad = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$mem = Get-CimInstance Win32_OperatingSystem
$memFreeGB = [math]::Round($mem.FreePhysicalMemory / 1MB, 2)
$memTotalGB = [math]::Round($mem.TotalVisibleMemorySize / 1MB, 2)
$memUsedGB = [math]::Round($memTotalGB - $memFreeGB, 2)
Append-Html "CPU and RAM Usage" "CPU Load: $cpuLoad %`nRAM: $memUsedGB GB used / $memTotalGB GB total"

# Event Logs (System Errors & Warnings from last 48h)
Write-Host "→ Checking recent system event logs..." -ForegroundColor Yellow
$errors = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Level = 2
    StartTime = (Get-Date).AddDays(-2)
} -ErrorAction SilentlyContinue

$warnings = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Level = 3
    StartTime = (Get-Date).AddDays(-2)
} -ErrorAction SilentlyContinue

Append-Html "System Errors (48h)" ($errors | Select-Object -First 10 | Format-Table TimeCreated, Id, Message -Wrap | Out-String)
Append-Html "System Warnings (48h)" ($warnings | Select-Object -First 10 | Format-Table TimeCreated, Id, Message -Wrap | Out-String)

# DISM Scans
Write-Host "→ Running DISM check..." -ForegroundColor Yellow
Append-Html "DISM CheckHealth" (dism /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String)
Append-Html "DISM ScanHealth" (dism /Online /Cleanup-Image /ScanHealth 2>&1 | Out-String)

# System File Checker
Write-Host "→ Running System File Checker..." -ForegroundColor Yellow
Append-Html "System File Checker (SFC)" (sfc /scannow 2>&1 | Out-String)

# Disk Usage
Write-Host "→ Gathering disk usage stats..." -ForegroundColor Yellow
$drives = Get-PSDrive -PSProvider FileSystem
$diskInfo = $drives | Select-Object Name,
    @{Name='Free(GB)'; Expression = { "{0:N2}" -f ($_.Free / 1GB) }},
    @{Name='Used(GB)'; Expression = { "{0:N2}" -f (($_.Used) / 1GB) }},
    @{Name='Total(GB)'; Expression = { "{0:N2}" -f (($_.Used + $_.Free) / 1GB) }}
Append-Html "Disk Usage" ($diskInfo | Out-String)

# Disk SMART Status (if available)
Write-Host "→ Checking SMART status..." -ForegroundColor Yellow
$smartData = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue
if ($smartData) {
    $smartInfo = $smartData | Select-Object InstanceName, PredictFailure
    Append-Html "SMART Drive Status" ($smartInfo | Format-Table -AutoSize | Out-String)
} else {
    Append-Html "SMART Drive Status" "SMART data not available on this system or access denied."
}

# Temp Cleanup
Write-Host "→ Cleaning temp files..." -ForegroundColor Yellow
$cleared = $false
try {
    $tempFiles = Get-ChildItem "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    $tempFiles | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    $cleared = $true
} catch {
    $cleared = $false
}
$cleanupStatus = if (-not $cleared) { 'FAILED' } else { 'OK' }
Append-Html "Temp File Cleanup" "Status: $cleanupStatus"

# Windows Update Summary
Write-Host "→ Getting recent Windows Update history..." -ForegroundColor Yellow
$WU = Get-CimInstance Win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5
Append-Html "Recent Windows Updates" ($WU | Format-Table HotFixID, Description, InstalledOn -AutoSize | Out-String)

# Critical Services
Write-Host "→ Checking critical services..." -ForegroundColor Yellow
$services = "wuauserv","bits","WinDefend","EventLog","Schedule"
$svcStatus = Get-Service -Name $services | Select-Object Name, DisplayName, Status, StartType
Append-Html "Critical Services" ($svcStatus | Format-Table -AutoSize | Out-String)

# Finalize Report
$html += "</body></html>"
$html | Out-File -Encoding UTF8 -FilePath $ReportPath

Write-Host "`n===> System diagnostics complete." -ForegroundColor Green
Write-Host "→ HTML Report saved to: $ReportPath" -ForegroundColor Cyan
