param($fqdn)

# Check for MSDeploy
$MSDeployPath = "$env:ProgramFiles\IIS\Microsoft Web Deploy V3\msdeploy.exe"
if (!(Test-Path($MSDeployPath)))
{
	Write-Output "Downloading MSDeploy Installer"
	$url = "https://download.microsoft.com/download/0/1/D/01DC28EA-638C-4A22-A57B-4CEF97755C6C/WebDeploy_amd64_en-US.msi"
	Invoke-WebRequest $url -OutFile "$env:temp\msdeploy.msi" -UseBasicParsing
	Write-Output "Installing MSDeploy";
	Start-Process "$env:temp\msdeploy.msi" -ArgumentList '/quiet', '/qn', '/norestart' -Wait

	Write-Output "Enabling WinRM";
	Enable-PSRemoting –force
	winrm quickconfig

	Write-Output "Generating Thumbprint";
	$thumbprint = (New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $fqdn).Thumbprint

	Write-Output "Creating HTTPS Listener";
	$cmd = 'winrm create winrm/config/listener?Address=*+Transport=HTTPS `@`{Hostname=`"$fqdn`"`; CertificateThumbprint=`"$thumbprint`"`}'

	Write-Output $cmd;
	Invoke-Expression $cmd
	
	Write-Output "Adding firewall rule"
	netsh advfirewall firewall add rule name="winRM HTTPS" dir=in action=allow protocol=TCP localport=5986
}
else{
  Write-Output "MSDeploy already installed."
}
