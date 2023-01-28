Write-Host "Capture current free disk space on Drive C" -foreground yellow
$FreespaceBefore = (Get-WmiObject win32_logicaldisk -Filter "DeviceID='C:'" | Select-Object Freespace).FreeSpace / 1GB

function Delete-ComputerRestorePoints {
	[CmdletBinding(SupportsShouldProcess = $True)] param(
		[Parameter(
			Position = 0,
			Mandatory = $true,
			ValueFromPipeline = $true
		)]
		$restorePoints
	)
	begin {
		$fullName = "SystemRestore.DeleteRestorePoint"
		#check if the type is already loaded
		$isLoaded = ([AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetTypes() } | Where-Object { $_.FullName -eq $fullName }) -ne $null
		if (!$isLoaded) {
			$SRClient = Add-Type -MemberDefinition @"
		    	[DllImport ("Srclient.dll")]
		        public static extern int SRRemoveRestorePoint (int index);
"@ -Name DeleteRestorePoint -Namespace SystemRestore -PassThru
		}
	}
	process {
		foreach ($restorePoint in $restorePoints) {
			if ($PSCmdlet.ShouldProcess("$($restorePoint.Description)","Deleting Restorepoint")) {
				[SystemRestore.DeleteRestorePoint]::SRRemoveRestorePoint($restorePoint.SequenceNumber)
			}
		}
	}
}


function Cleanup {

	function global:Write-Verbose ([string]$Message)

	# check $VerbosePreference variable, and turns -Verbose on
	{ if ($VerbosePreference -ne 'SilentlyContinue')
		{ Write-Host " $Message" -ForegroundColor 'Yellow' }
	}

	$VerbosePreference = "Continue"
	$DaysToDelete = 7
	$LogDate = Get-Date -Format "MM-d-yy-HH"
	$objShell = New-Object -ComObject Shell.Application
	$objFolder = $objShell.Namespace(0xA)
	$ErrorActionPreference = "silentlycontinue"

	Start-Transcript -Path C:\$LogDate.log
	Clear-Host
	Write-Host "Audit Log Started..." -foreground green
	Write-Host "Clean Procedure is Starting..." -foreground yellow
	$size = Get-ChildItem C:\Users\* -Include *.iso,*.vhd -Recurse -ErrorAction SilentlyContinue |
	Sort Length -Descending |
	Select-Object Name,Directory,
	@{ Name = "Size (GB)"; Expression = { "{0:N2}" -f ($_.Length / 1GB) } } |
	Format-Table -AutoSize | Out-String

	$Before = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
	@{ Name = "Drive"; Expression = { ($_.DeviceID) } },
	@{ Name = "Size (GB)"; Expression = { "{0:N1}" -f ($_.Size / 1gb) } },
	@{ Name = "FreeSpace (GB)"; Expression = { "{0:N1}" -f ($_.FreeSpace / 1gb) } },
	@{ Name = "PercentFree"; Expression = { "{0:P1}" -f ($_.FreeSpace / $_.Size) } } |
	Format-Table -AutoSize | Out-String

	Write-Host "Clean Procedure is Starting..." -foreground green

	Get-Service -Name wuauserv | Stop-Service -Force -Verbose -ErrorAction SilentlyContinue
	Write-Host "Windows Update Service has been stopped successfully" -foreground green

	Write-Host "Delete windows software distribution store." -foreground red
	Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
	Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(- $DaysToDelete)) } |
	Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue
	Write-Host "Cleared Windows Software Distribution" -foreground green

	## Deletes  the Windows Temp folder.
	Write-Host "Delete windows temp store." -foreground red
	Get-ChildItem "C:\Windows\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
	Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(- $DaysToDelete)) } |
	Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue
	Write-Host "Cleared Windows Temp" -foreground green

	## Delets all files and folders in user's Temp folder. 
	Write-Host "Delete windows temp store." -foreground red
	Get-ChildItem "C:\users\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue |
	Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(- $DaysToDelete)) } |
	Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue
	Write-Host "Cleared C:\users\$env:USERNAME\AppData\Local\Temp\" -foreground green

	## Remove all files and folders in user's Temporary Internet Files. 
	Write-Host "Delete windows user temp store." -foreground red
	Get-ChildItem "C:\users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" `
 		-Recurse -Force -Verbose -ErrorAction SilentlyContinue |
	Where-Object { ($_.CreationTime -le $(Get-Date).AddDays(- $DaysToDelete)) } |
	Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Cleared windows user temp store." -foreground green

	## All Temporary Internet Files have been removed successfully!

	Write-Host "Check for IIS serv logs." -foreground cyan
	Write-Host "Delete IIS serv logs." -foreground red
	Get-ChildItem "C:\inetpub\logs\LogFiles\*" -Recurse -Force -ErrorAction SilentlyContinue |
	Where-Object { ($_.CreationTime -le $(Get-Date).AddDays(-30)) } |
	Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue
	Write-Host "Cleared IIS serv logs." -foreground green

	## All IIS Logfiles over x days old have been removed Successfully!

	## deletes Cleared the recycling Bin.
	## The Recycling Bin is now being emptied!
	Write-Host "Delete System & user Recycle Bins." -foreground red

	$objFolder.items() | ForEach-Object { Remove-Item $_.path -ErrorAction Ignore -Force -Verbose -Recurse }
	Write-Host "Cleared System & user Recycle Bins." -foreground green

	## The Recycling Bin has been emptied!

	## Starts the Windows Update Service
	##Get-Service -Name wuauserv | Start-Service -Verbose



	Write-Host "Deleting System Restore Points" -foreground red
	Get-ComputerRestorePoint | Delete-ComputerRestorePoints # -WhatIf

	Write-Host "Checking to make sure you have Local Admin rights" -foreground cyan
	if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
	{
		Write-Warning "Please run this script as an Administrator!" -foreground red
		if (!($psISE)) { "Press any key to continue "; [void][System.Console]::ReadKey($true) }
		exit 1
	}


	Write-Host "Deleting Rouge folders" -foreground red
	if (Test-Path C:\Config.Msi) { Remove-Item -Path C:\Config.Msi -Force -Recurse }
	Write-Host "Cleared config.msi" -foreground green

	if (Test-Path c:\Intel) { Remove-Item -Path c:\Intel -Force -Recurse }
	Write-Host "Cleared Intel folders" -foreground green

	if (Test-Path c:\PerfLogs) { Remove-Item -Path c:\PerfLogs -Force -Recurse }
	Write-Host "Cleared Perflogs" -foreground green

	if (Test-Path $env:windir\memory.dmp) { Remove-Item $env:windir\memory.dmp -Force }
	Write-Host "Cleared win32 folders" -foreground green


	Write-Host "Deleting Windows Error Reporting files" -foreground yellow
	if (Test-Path C:\ProgramData\Microsoft\Windows\WER) { Get-ChildItem -Path C:\ProgramData\Microsoft\Windows\WER -Recurse | Remove-Item -Force -Recurse }
	Write-Host "Cleared Windows Error Reporting files" -foreground green

	Write-Host "Removing System and User Temp Files" -foreground yellow
	Remove-Item -Path "$env:windir\Temp\*" -Force -Recurse
	Remove-Item -Path "$env:windir\minidump\*" -Force -Recurse
	Remove-Item -Path "$env:windir\Prefetch\*" -Force -Recurse
	Remove-Item -Path "C:\Users\*\AppData\Local\Temp\*" -Force -Recurse
	Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\WER\*" -Force -Recurse
	Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Force -Recurse
	Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatCache\*" -Force -Recurse
	Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatUaCache\*" -Force -Recurse
	Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\*" -Force -Recurse
	Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*" -Force -Recurse
	Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\*" -Force -Recurse
	Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\*" -Force -Recurse
	Write-Host "Cleared System and User Temp Files" -foreground green


	Write-Host "Removing Windows Updates Downloads" -foreground yellow
	Stop-Service wuauserv -Force -Verbose
	Stop-Service TrustedInstaller -Force -Verbose
	Write-Host "Stopped Winserv & Install Svcs" -foreground cyan

	Remove-Item -Path "$env:windir\SoftwareDistribution\*" -Force -Recurse
	Write-Host "Cleared Software Distribution" -foreground green

	Remove-Item $env:windir\Logs\CBS\* -Force -Recurse
	Write-Host "Cleared logs" -foreground green

	Start-Service wuauserv -Verbose
	Start-Service TrustedInstaller -Verbose
	Write-Host "ReStarted Winserv & Install Svcs" -foreground cyan


	Write-Host "Checkif Windows Cleanup exists" -foreground yellow
	#Mainly for 2008 servers
	if (!(Test-Path c:\windows\System32\cleanmgr.exe)) {
		Write-Host "Windows Cleanup NOT installed now installing" -foreground yellow
		Copy-Item $env:windir\winsxs\amd64_microsoft-windows-cleanmgr_31bf3856ad364e35_6.1.7600.16385_none_c9392808773cd7da\cleanmgr.exe $env:windir\System32
		Copy-Item $env:windir\winsxs\amd64_microsoft-windows-cleanmgr.resources_31bf3856ad364e35_6.1.7600.16385_en-us_b9cb6194b257cc63\cleanmgr.exe.mui $env:windir\System32\en-US
	}


	Write-Host "Running Windows System Cleanup" -foreground yellow
	#Set StateFlags setting for each item in Windows disk cleanup utility
	$StateFlags = 'StateFlags0013'
	$StateRun = $StateFlags.Substring($StateFlags.get_Length() - 2)
	$StateRun = '/sagerun:' + $StateRun
	if (-not (Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders' -Name $StateFlags)) {
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\BranchCache' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Memory Dump Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Service Pack Cleanup' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Archive Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Queue Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Archive Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Queue Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Temp Files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows ESD installation files' -Name $StateFlags -Type DWORD -Value 2
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files' -Name $StateFlags -Type DWORD -Value 2
	}

	Write-Host "Starting CleanMgr.exe.." -foreground yellow
	Start-Process -FilePath CleanMgr.exe -ArgumentList $StateRun -WindowStyle Hidden -Wait

	Write-Host "Clearing All Event Logs" -foreground yellow
	wevtutil el | ForEach-Object { Write-Host "Clearing $_"; wevtutil cl "$_" }

	Write-Host "Getting the list of users" -forground cyan
	# Write Information to the screen
	Write-Host "Exporting the list of users to c:\users\%username%\users.csv" -forground cyan
	# List the users in c:\users and export to the local profile for calling later
	Get-ChildItem C:\Users | Select-Object Name | Export-Csv -Path C:\users\$env:USERNAME\users.csv -NoTypeInformation
	$list = Test-Path C:\users\$env:USERNAME\users.csv
	""
	"-------------------"
	Write-Host "Moving On..." -forground cyan
	"-------------------"
	if ($list) {
		"-------------------"
		#Clear Mozilla Firefox Cache
		Write-Host "Clearing Mozilla Firefox Caches" -foreground red
		"-------------------"
		Write-Host "Clearing Mozilla caches" -foreground red
		Write-Host -ForegroundColor cyan
		Import-Csv -Path C:\users\$env:USERNAME\users.csv -Header Name | ForEach-Object {
			Remove-Item -Path C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache\* -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache\*.* -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache2\* -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache2\*.* -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\thumbnails\* -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\cookies.sqlite -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\webappsstore.sqlite -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\chromeappsstore.sqlite -Recurse -Force -EA SilentlyContinue -Verbose
		}
		Write-Host "Clearing Mozilla caches" -foreground green
		Write-Host "Done..." -foreground green
		""
		"-------------------"
		# Clear Google Chrome
		Write-Host -ForegroundColor Green "Clearing Google Chrome Caches" -foreground red
		"-------------------"
		Write-Host -ForegroundColor Blue "Clearing Google caches" -foreground red
		Write-Host -ForegroundColor Black
		Import-Csv -Path C:\users\$env:USERNAME\users.csv -Header Name | ForEach-Object {
			Remove-Item -Path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Cache\*" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Cache2\entries\*" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Media Cache" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies-Journal" -Recurse -Force -EA SilentlyContinue -Verbose
			# Comment out the following line to remove the Chrome Write Font Cache too.
			# Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\ChromeDWriteFontCache" -Recurse -Force -EA SilentlyContinue -Verbose
		}

		Write-Host -ForegroundColor Blue "Done..."
		""
		"-------------------"
		# Clear Internet Explorer
		Write-Host -ForegroundColor Green "Clearing Internet Explorer Caches"
		"-------------------"
		Write-Host -ForegroundColor Green "Clearing Google caches"
		Write-Host -ForegroundColor Black
		Import-Csv -Path C:\users\$env:USERNAME\users.csv | ForEach-Object {
			Remove-Item -Path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\WER\*" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path "C:\Users\$($_.Name)\AppData\Local\Temp\*" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -Path "C:\`$recycle.bin\" -Recurse -Force -EA SilentlyContinue -Verbose
		}

		Write-Host -ForegroundColor Red "Done..."

		Write-Host -ForegroundColor green "Completed Internet Cleanup!"
		Remove-Item C:\users\$env:USERNAME\users.csv
		Write-Host -ForegroundColor green "User file removed"

	} else {
		Write-Host -ForegroundColor red "Session Cancelled"
		Remove-Item C:\users\$env:USERNAME\users.csv

	}

	## Disk Defragementaion

	$computer = $env:computername

	#Get all local disks on the local computer via WMI class Win32_Volume
	Get-WmiObject -ComputerName $computer -Class win32_volume | Where-Object { $_.DriveType -eq 3 -and $_.driveletter -ne $null } |

	#Perform a defrag analysis on each disk returned
	ForEach-Object -Begin {} -Process {

		#Initialise properties hashtable
		$properties = @{}

		#perform the defrag analysis
		Write-Verbose $('Analyzing volume ' + $_.driveletter + ' on computer ' + $computer)
		$results = $_.DefragAnalysis()

		# #if the return code is 0 the operation was successful so output the results using the properties hashtable
		if ($results.ReturnValue -eq 0) {
			$properties.Add("ComputerName",$_.__Server)
			$properties.Add("DriveLetter",$_.driveletter)
			if ($_.DefragAnalysis().DefragRecommended -eq $true) { $properties.Add("DefragRequired",$true) } else { $properties.Add("DefragRequired",$false) }
			if (($_.FreeSpace / 1GB) -gt (($_.Capacity / 1GB) * 0.15)) { $properties.Add("SufficientFreeSpace",$true) } else { $properties.Add("SufficientFreeSpace",$false) }
			Write-Verbose “Analysis complete”
			New-Object PSObject -Property $properties
		 }
		# #If the return code is 1 then access to perform the defag analysis was denied
		elseif ($results.ReturnValue -eq 1) {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: Access Denied”)
		}
		# #If the return code is 2 defragmentation is not supported for the device specified
		elseif ($results.ReturnValue -eq 2) {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: Defrag is not supported for this volume”)
		}
		# #If the return code is 3 defrag analysis cannot be performed as the dirty bit is set for the device
		elseif ($results.ReturnValue -eq 3) {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: The dirty bit is set for this volume”)
		}
		# #If the return code is 4 there is not enough free space to perform defragmentation
		elseif ($results.ReturnValue -eq 4) {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: The is not enough free space to perform this action”)
		}
		# #If the return code is 5 defragmentation cannot be performed as a corrupt Master file table was detected
		elseif ($results.ReturnValue -eq 5) {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: Possible Master File Table corruption”)
		}
		# #If the return code is 6 or 7 the operation was cancelled
		elseif ($results.ReturnValue -eq 6 -or $results.ReturnValue -eq 7) {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: The operation was cancelled”)
		}
		# #If the return code is 8 the defrag engine is already running
		elseif ($results.ReturnValue -eq 8) {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: The defragmentation engine is already running”)
		}
		# #If the return code is 9 the script could not connect to the defrag engine on the machine specified
		elseif ($results.ReturnValue -eq 9) {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: Could not connect to the defrag engine”)
		}
		# #If the return code is 10 a degrag engine error occured
		elseif ($results.ReturnValue -eq 10) {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: A defrag engine error occured”)
		}
		# #Else an unknown error occured
		else {
			Write-Output (“Defrag analysis for disk ” + $_.driveletter + ” on computer ” + $_.__Server + ” failed: An unknown error occured”)
		}
		Write-Verbose “Analysis complete”
			New-Object PSObject -Property $properties

	} #Close ForEach loop for Defrag Analysis

	#Close else clause on test-computer if conditional

	## Disk Space After Maintenance
	Write-Host "Defrag Operation start" -foreground yellow
	Optimize-Volume c -Verbose
	Write-Host "Disk Usage before and after cleanup" -foreground yellow
	$FreespaceAfter = (Get-WmiObject win32_logicaldisk -Filter "DeviceID='C:'" | Select-Object Freespace).FreeSpace / 1GB
	"Free Space Before: {0}" -f $FreespaceBefore
	"Free Space After: {0}" -f $FreespaceAfter


	$After = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
	@{ Name = "Drive"; Expression = { ($_.DeviceID) } },
	@{ Name = "Size (GB)"; Expression = { "{0:N1}" -f ($_.Size / 1gb) } },
	@{ Name = "FreeSpace (GB)"; Expression = { "{0:N1}" -f ($_.FreeSpace / 1gb) } },
	@{ Name = "PercentFree"; Expression = { "{0:P1}" -f ($_.FreeSpace / $_.Size) } } |
	Format-Table -AutoSize | Out-String

	## Sends some before and after info for ticketing purposes

	Hostname; Get-Date | Select-Object DateTime
	Write-Verbose "Before: $Before"
	Write-Verbose "After: $After"
	Write-Verbose $size
	Write-Host "Written by Mike Izzo - =)" -foreground cyan

	## Completed Successfully!
} Cleanup

Stop-Transcript