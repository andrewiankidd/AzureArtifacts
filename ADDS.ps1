param(

	[string]$adminUser = "devops",
	
	[string]$adminPass = "",
	
	[string]$deployIndex = "0",
	
	[string]$domainName = "amcsplatform.local",
	
	[string]$netBiosName = "AMCSPLATFORM",
	
	[ValidateSet('Win2008', 'Win2008R2', 'Win2012', 'Win2012R2', 'WinThreshold', 'Default')]
	[string]$domainMode = 'Default'
)

# Initialize storage drive.
if (!(Test-Path "F:")){
	# Init
	Write-Output "Initializing Storage drive...";
	
	# Begin
	Get-Disk | Where-Object {$_.PartitionStyle -eq 'RAW'} | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -DriveLetter "F" -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "ADDSDrive";
	
	# Complete
	Write-Output "Done.";
}

# Create PSCredentials object
Write-Output "Adding Computer to domain"
$credStore = New-Object System.Management.Automation.PSCredential($adminUser, ($adminPass | ConvertTo-SecureString -AsPlainText -Force));

# Add the missing windows features
Write-Output "Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools";
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools;

# Import the relevant module(s)
Write-Output "Import-Module ADDSDeployment";
Import-Module ADDSDeployment;

# Flush DNS as prep
Write-Output "IPCONFIG /FLUSHDNS";
& IPCONFIG /FLUSHDNS;
	
Write-Output "`$deployIndex: $deployIndex";
if ($deployIndex -eq 1) {

	# Creating Domain/Forest
	Write-Output "Install-ADDSForest";
	Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "F:\NTDS" -DomainMode "$domainMode" -DomainName "$domainName" -DomainNetbiosName "$netBiosName" -ForestMode "$domainMode" -InstallDns:$true -LogPath "F:\NTDS" -NoRebootOnCompletion:$true -SysvolPath "F:\SYSVOL" -Force:$true -SafeModeAdministratorPassword ($adminPass | ConvertTo-SecureString -AsPlainText -Force);

} else {

	# Add machine to the domain group
	try {
		Add-Computer -DomainName "$domainName" -Credential $credStore -ErrorAction Stop;
	} catch {
		if ($_.Exception.Message.Contains("already in that domain")) {
			Write-Warning $_.Exception.Message;
		} else {
			Write-Error $_.Exception.Message;
		}
	}

	# Joining Domain/Forest
	Write-Output "Install-ADDSDomainController";
	Install-ADDSDomainController -CreateDnsDelegation:$false -DatabasePath "F:\NTDS" -DomainName "$domainname" -NoGlobalCatalog:$false -Credential $credStore -CriticalReplicationOnly:$false -InstallDns:$false -LogPath "F:\NTDS" -NoRebootOnCompletion:$true -SiteName:$netBiosName -SysvolPath "F:\SYSVOL" -Force:$true

}

Write-Output "Complete."
