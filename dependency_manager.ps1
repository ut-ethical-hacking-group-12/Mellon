Write-Host "Checking dependencies..."

# Download fgdump
if(!(Test-Path $PSScriptRoot\fgdump.exe)) {
    Write-Host "Downloading fgdump.exe..."
    $url = "https://s3.amazonaws.com/mellondefender.tools/fgdump.exe"
    $output = "$PSScriptRoot\fgdump.exe"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source $url -Destination $output
    Write-Host "Complete!"
}

#Download John
if(!(Test-Path $PSScriptRoot\john180j1w)) {
    Write-Host "Downloading john180j1w.zip..."
    $url = "https://s3.amazonaws.com/mellondefender.tools/john180j1w.zip"
    $output = "$PSScriptRoot\john180j1w.zip"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source $url -Destination $output
    Expand-Archive $PSScriptRoot\john180j1w.zip -DestinationPath $PSScriptRoot
    Write-Host "Complete!"
}
Remove-Item $PSScriptRoot\john180j1w.zip -ErrorAction SilentlyContinue

#Download rockyou
if (!(Test-Path $PSScriptRoot\rockyou.txt)) {
    Write-Host "Downloading rockyou.txt.zip..."
    $url = "https://s3.amazonaws.com/mellondefender.tools/rockyou.txt.zip"
    $output = "$PSScriptRoot\rockyou.txt.zip"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source $url -Destination $output
    Expand-Archive $PSScriptRoot\rockyou.txt.zip -DestinationPath $PSScriptRoot
    Write-Host "Complete!"
}
Remove-Item $PSScriptRoot\rockyou.txt.zip -ErrorAction SilentlyContinue
Remove-Item $PSScriptRoot\__MACOSX -Recurse -ErrorAction SilentlyContinue

Write-Host "Done checking dependencies."
Read-Host -Prompt "Press Enter to exit"


