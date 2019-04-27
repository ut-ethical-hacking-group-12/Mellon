$username_array = @()
$password_array = @()
Add-Type -AssemblyName System.Web
ForEach($name in Get-Content -Path .\usernames.txt) {
    if($name.length -gt 0) {
        $password = [System.Web.Security.Membership]::GeneratePassword(12,5)
        Write-Host $name
        Write-Host $password
        $secure_string = (ConvertTo-SecureString -AsPlainText "$password" -Force)
        $username_array += $name
        $password_array += $secure_string
        Set-ADAccountPassword -Identity $name -Reset -NewPassword $secure_string
    }
}

Read-Host -Prompt "Press Enter to exit"
