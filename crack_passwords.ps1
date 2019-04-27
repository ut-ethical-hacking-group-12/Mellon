
Remove-Item john_results.txt -ErrorAction SilentlyContinue
Remove-Item usernames.txt -ErrorAction SilentlyContinue

& ".\john180j1w\run\john" "-wordlist:./rockyou.txt" "-format=NT" "./hashes.txt"
& ".\john180j1w\run\john" "--show" "./hashes.txt" > john_results.txt

#Get-Content john_results.txt Select-String -Pattern (\w*):(\w*) % { $_.Matches } foreach { Write-Output "$($_.Groups[1]):$($_.Groups[2])" } > usernames.txt

ForEach($line in Get-Content -Path .\john_results.txt) {
    $result = $line.Split(':')
    if($result[0].contains(' ')) {
        break
    }
    if(!($result[1] -eq "NO PASSWORD")) {
        Add-Content -Path usernames.txt -Value $result[0] 
    }
}

Read-Host -Prompt "Press Enter to exit"
