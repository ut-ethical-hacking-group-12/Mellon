& ".\john\run\john -wordlist:./rockyou.txt -format=<format> ./hashes.txt"
& ".\john\run\john --show ./hashes.txt > john_results.txt"

Get-Content john_results.txt |
Select-String -Pattern (\w*):(\w*) |
% { $_.Matches } |
foreach { Write-Output "$($_.Groups[1]):$($_.Groups[2])" } > usernames.txt
