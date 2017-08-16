Write-Host "addStartupItems.ps1"

$cd = Get-Location;
$zipPath = "$cd\startupItems.zip"
$startupPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$unzipPath = "$cd\startupUnzip"
if (Test-Path($unzipPath)){
    Remove-Item -path $unzipPath -force -recurse
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
Write-Host "extracting startup-items to startup directory..."
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, "$unzipPath")
copy "$unzipPath\*" "$startupPath\" -force -recurse