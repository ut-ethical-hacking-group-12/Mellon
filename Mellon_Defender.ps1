Import-Module ActiveDirectory
Import-Module BitsTransfer

$raw = Get-Content .\config.json -Raw
$config = ConvertFrom-Json -InputObject $raw

function Write-Info { 

    Param ($in)
    Write-Host "[*] $in"
}

function Write-Good { 

    Param ($in)
    Write-Host "[+] $in"
}

function Write-Bad { 

    Param ($in)
    Write-Host "[-] $in"
}

function Write-Banner {
    Write-Info "[==========] MELLON_DEFENDER.PS1 [==========]"
}

function Get-Dependencies {

    Write-Bad "Disabling Windows Defender."
    Set-MpPreference -DisableRealtimeMonitoring $true
    Write-Info "Checking dependencies..."

    # Download fgdump
    if(!(Test-Path $PSScriptRoot\fgdump.exe)) {
        Write-Info "> Downloading fgdump.exe..."
        $url = "https://s3.amazonaws.com/mellondefender.tools/fgdump.exe"
        $output = "$PSScriptRoot\fgdump.exe"
        Start-BitsTransfer -Source $url -Destination $output
        Write-Good "> Download complete!"
    }

    #Download John
    if(!(Test-Path $PSScriptRoot\john180j1w)) {
        Write-Info "> Downloading john180j1w.zip..."
        $url = "https://s3.amazonaws.com/mellondefender.tools/john180j1w.zip"
        $output = "$PSScriptRoot\john180j1w.zip"
        Start-BitsTransfer -Source $url -Destination $output
        Write-Good "> Download complete!"
        Write-Info "> Extracting..."
        Expand-Archive $PSScriptRoot\john180j1w.zip -DestinationPath $PSScriptRoot
        Write-Good "> Extraction complete!"
    }
    Remove-Item $PSScriptRoot\john180j1w.zip -ErrorAction SilentlyContinue

    #Download rockyou
    if (!(Test-Path $PSScriptRoot\rockyou.txt)) {
        Write-Info "> Downloading rockyou.txt.zip..."
        $url = "https://s3.amazonaws.com/mellondefender.tools/rockyou.txt.zip"
        $output = "$PSScriptRoot\rockyou.txt.zip"
        Start-BitsTransfer -Source $url -Destination $output
        Write-Good "> Download complete!"
        Write-Info "> Extracting..."
        Expand-Archive $PSScriptRoot\rockyou.txt.zip -DestinationPath $PSScriptRoot
        Write-Good "> Extraction complete!"
    }
    Remove-Item $PSScriptRoot\rockyou.txt.zip -ErrorAction SilentlyContinue
    Remove-Item $PSScriptRoot\__MACOSX -Recurse -ErrorAction SilentlyContinue

    Write-Good "Done checking dependencies."
}

function Get-Hashes {

    Remove-Item hashes.txt -ErrorAction SilentlyContinue  

    Write-Info "Retrieving SAM database hashes..."
    start-process $PSScriptRoot\fgdump.exe

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
    Write-Good "Hashes retrieved!"

    Remove-Item $PSScriptRoot\fgdump.exe
    Rename-Item -Path $PSScriptRoot\127.0.0.1.pwdump -NewName hashes.txt
    Remove-Item $PSScriptRoot\127.0.0.1.cachedump -ErrorAction SilentlyContinue
    ls *.fgdump-log -Recurse | foreach {rm $_}

    Write-Good "Enabling Windows Defender."
    Set-MpPreference -DisableRealtimeMonitoring $false
}

function Get-Passwords {

    Remove-Item john_results.txt -ErrorAction SilentlyContinue

    $null = & ".\john180j1w\run\john" "-wordlist:./rockyou.txt" "-format=NT" "./hashes.txt"
    $null = & ".\john180j1w\run\john" "--show" "./hashes.txt" > john_results.txt

    $users = @()
    $count = 0

    ForEach($line in Get-Content -Path .\john_results.txt) {
        $array = $line.Split(':')
        if($array.length -gt 1) {
            $username = $array[0]
            $password = $array[1]
            if(!($password -eq "NO PASSWORD")) {
                $users += $username 
                $count++
            }
        } else {
            break
        }
    }

    Remove-Item john_results.txt
    Remove-Item hashes.txt

    return $users
}

function Update-Passwords {

    Param ([array]$users)

    $passwords = @()
    Add-Type -AssemblyName System.Web
    ForEach($name in $users) {
        if($name.length -gt 0) {
            $password = [System.Web.Security.Membership]::GeneratePassword(12,5)
            $secure_string = (ConvertTo-SecureString -AsPlainText "$password" -Force)
            $passwords += $secure_string
            Set-ADAccountPassword -Identity $name -Reset -NewPassword $secure_string
            Set-ADUser -Identity $name -PasswordNeverExpires $false -ChangePasswordAtLogon $true
            Write-Good "> Password updated for $name."
        }
    }

    return $passwords
}

function Notify-Users {

    Param ($recipients, $passwords)

    $smtp_passwd = ConvertTo-SecureString $config.smtp_password -AsPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential($config.smtp_username, $smtp_passwd) 

    For ($index = 0; $index -lt $recipients.length; $index++) {

        $recipient = Get-ADUser $recipients[$index] -Properties mail
        $securePassword = $passwords[$index]

        #Converting SecureString to String
        $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordPointer)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)

        $timestamp = (Get-Date).ToString('MM/dd/yyyy hh:mm:ss tt')
        Send-MailMessage -From $config.sender_email -Subject "Password Reset Notification, $timestamp" -To $recipient.mail -Body "This is a notification that your Windows domain credentials were deemed to be insecure through testing initiated by your network administrator. Your password has been set to $password and will need to be reset the next time you log in. " -Credential $credentials -SmtpServer $config.smtp_server -UseSsl
    }

}

Write-Host "


     dBBBBBBb  dBBBP  dBP    dBP    dBBBBP dBBBBb
      '   dB'                      dB'.BP     dBP
   dB'dB'dB' dBBP   dBP    dBP    dB'.BP dBP dBP 
  dB'dB'dB' dBP    dBP    dBP    dB'.BP dBP dBP  
 dB'dB'dB' dBBBBP dBBBBP dBBBBP dBBBBP dBP dBP   

 "
Write-Banner
Get-Dependencies
Get-Hashes
$users = @(Get-Passwords)
$count = $users.length
if($count -gt 0) {
    Write-Bad "Cracked $count accounts. Issuing password changes to affected users: $users"
    $passwords = @(Update-Passwords $users)
    Notify-Users $users $passwords
} else {
    Write-Good "No vulnerable users detected!"
}
Write-Banner

Read-Host "Press ENTER to quit"