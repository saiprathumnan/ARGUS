# Nightly backup
Get-ChildItem C:\Data -Recurse | Compress-Archive -DestinationPath D:\Backups\data.zip -Force
Write-Output 'done'
