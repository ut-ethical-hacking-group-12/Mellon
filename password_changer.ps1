$username_array = @()
$password_array = @()
Add-Type -AssemblyName System.Web
ForEach($name in Get-Content -Path .\usernames.txt) {
    $password = [System.Web.Security.Membership]::GeneratePassword(24,5)
    Write-Host $name
    Write-Host $password
    $secure_string = (ConvertTo-SecureString -AsPlainText "$password" -Force)
    $username_array += $name
    $password_array += $secure_string
    Set-ADAccountPassword –Identity $name –Reset –NewPassword $secure_string
    
}
