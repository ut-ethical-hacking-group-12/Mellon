#notify_users.ps1

import-module activedirectory

$raw = Get-Content .\config.json -Raw
$config = ConvertFrom-Json -InputObject $raw

Param(
    [Parameter(Mandatory = $true)]
    [string[]]$recipients,
    [Parameter(Mandatory = $true)]
    [Security.SecureString[]]$passwords
)

$smtp_passwd = ConvertTo-SecureString $config.smtp_password -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($config.smtp_username, $smtp_passwd) 

For ($index = 0; $index -lt $recipients.Length; $index++) {

    $recipient = Get-ADUser $recipients[$index] -Properties mail
    $securePassword = $passwords[$index]

    #Converting SecureString to String
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordPointer)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)

    $timestamp = (Get-Date).ToString('MM/dd/yyyy hh:mm:ss tt')
    Send-MailMessage -From $config.sender_email -Subject "Password Reset Notification, $timestamp" -To $recipient.mail -Body "This is a notification that your Windows domain credentials were deemed to be insecure through testing initiated by your network administrator. Your password has been set to $password and will need to be reset the next time you log in. " -Credential $credentials -SmtpServer $config.smtp_server -UseSsl
}

#Read-Host -Prompt "Press Enter to exit"
