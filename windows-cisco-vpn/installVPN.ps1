Write-Host "installVPN.ps1"
$profilePath = "C:\Program Files (x86)\Cisco Systems\VPN Client\Profiles"
$pcffilename = "exampleprofile.pcf"

#########################################################
$cd = Get-Location;
if (Test-Path($profilePath)){
    Remove-Item -path $profilePath -force -recurse
}
if (Test-Path("$cd\VPNunzip\")){
    Remove-Item -path "$cd\VPNunzip\" -force -recurse
}

Write-Host "Extracting vpnItems to temp folder..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory("vpnItems.zip", "$cd\VPNunzip\")

Write-Host "Installing VPN Step 1.msi"

& msiexec /quiet /qn /norestart /passive /i "$cd\VPNunzip\VPN Step 1.msi" | Out-Null #Citrix DNE Update - Deterministic Network Enhancer for x64 Windows
Write-Host "Installing VPN Step 2.msi"
& msiexec /quiet /qn /norestart /passive /i "$cd\VPNunzip\VPN Step 2.msi" | Out-Null #Cisco Systems VPN Client for Windows 64-Bit

Write-Host "Copying AMCS Digiweb.pcf to VPN Directory"
copy "$cd\VPNunzip\$pcffilename" "$profilePath\$pcffilename" -force

Write-Host "Applying win10 registry fix"
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CVirtA' -Name DisplayName -Value "Cisco Systems VPN Adapter for 64-bit Windows"