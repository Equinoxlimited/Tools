# Define tools as hashtable of objects
$tools = @{
  1 = @{ Name = "Windows Update";       Command = "msdt.exe /id WindowsUpdateDiagnostic" }
  2 = @{ Name = "Network Adapter";      Command = "msdt.exe /id NetworkDiagnosticsNetworkAdapter" }
  3 = @{ Name = "Web Connectivity";     Command = "msdt.exe /id NetworkDiagnosticsWeb" }
  4 = @{ Name = "Shared Folders";       Command = "msdt.exe /id NetworkDiagnosticsFileShare" }
  5 = @{ Name = "Incoming Connections"; Command = "msdt.exe /id NetworkDiagnosticsInbound" }
  6 = @{ Name = "Audio Playback";       Command = "msdt.exe /id AudioPlaybackDiagnostic" }
  7 = @{ Name = "Audio Recording";      Command = "msdt.exe /id AudioRecordingDiagnostic" }
  8 = @{ Name = "Video Playback";       Command = "msdt.exe /id VideoPlaybackDiagnostic" }
  9 = @{ Name = "Hardware Devices";     Command = "msdt.exe /id DeviceDiagnostic" }
 10 = @{ Name = "Printer";              Command = "msdt.exe /id PrinterDiagnostic" }
 11 = @{ Name = "Power";                Command = "msdt.exe /id PowerDiagnostic" }
 12 = @{ Name = "System Maintenance";   Command = "msdt.exe /id MaintenanceDiagnostic" }
 13 = @{ Name = "Aero Desktop Effects"; Command = "msdt.exe /id AeroDiagnostic" }
 14 = @{ Name = "Windows Store Apps";   Command = "msdt.exe /id WindowsStoreDiagnostic" }
}

# Display menu
Write-Host "Equinox Limited - Troubleshooting Menu:`n"
foreach ($key in $tools.Keys | Sort-Object) {
    Write-Host "$key : $($tools[$key].Name)"
}

# Prompt
$choice = Read-Host "`nEnter number"

# Execute if valid
if ($tools.ContainsKey([int]$choice)) {
    $cmd = $tools[[int]$choice].Command
    Write-Host "Launching $($tools[[int]$choice].Name)..."
    Invoke-Expression $cmd
} else {
    Write-Host "Invalid selection."
}
