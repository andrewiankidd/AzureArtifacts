param ($adminUser, $adminPassword)
######################
# Settings
######################
if (!$adminUser)
{
    $adminUser = "sa"
}
if (!$adminPass)
{
    $adminPass = "Password123"
}

$hostname = $env:computername;

write-output "Downloading SQLServer"
Write-Output "------------------------------"

if (!(Test-Path("$env:temp\SQLFULL_x64_ENU_Core.box")))
{
	write-output "Downloading SQLServer Core..."
	$downloadURL = "https://download.microsoft.com/download/4/C/7/4C7D40B9-BCF8-4F8A-9E76-06E9B92FE5AE/ENU/x64/SQLFULL_x64_ENU_Core.box"
	$webClient.DownloadFile($downloadURL, "$env:temp\SQLFULL_x64_ENU_Core.box")
}

if (!(Test-Path("$env:temp\SQLFULL_x64_ENU_Lang.box")))
{
	write-output "Downloading SQLServer Language Files..."
	$downloadURL = "https://download.microsoft.com/download/4/C/7/4C7D40B9-BCF8-4F8A-9E76-06E9B92FE5AE/ENU/x64/SQLFULL_x64_ENU_Lang.box"
	$webClient.DownloadFile($downloadURL, "$env:temp\SQLFULL_x64_ENU_Lang.box")
}

if (!(Test-Path("$env:temp\SQLFULL_x64_ENU_Install.exe")))
{
	write-output "Downloading SQLServer Installer..."
	$downloadURL = "https://download.microsoft.com/download/4/C/7/4C7D40B9-BCF8-4F8A-9E76-06E9B92FE5AE/ENU/x64/SQLFULL_x64_ENU_Install.exe"
	$webClient.DownloadFile($downloadURL, "$env:temp\SQLFULL_x64_ENU_Install.exe")
}

Write-Output "Installing SQLServer";
Start-Process "$env:temp\SQLFULL_x64_ENU_Install.exe" -ArgumentList "/QS", "/ACTION=install", "/IACCEPTSQLSERVERLICENSETERMS=1", "/FEATURES=SQLENGINE", "/SQLSYSADMINACCOUNTS=$hostname\$adminUser", "/INSTANCENAME=$hostname\mssqlserver", "/INDICATEPROGRESS=True" -Wait

Write-Output "--------------------------------"
Write-Output "AMCS SQL Setup"
Write-Output "--------------------------------"
# Connect to the instance using SMO
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null
$sqlServer = new-object ("Microsoft.SqlServer.Management.Smo.Server") "."
write-output "Instance Name: $($sqlServer.Name)"
write-output "Instance Version: $($sqlServer.Version)"

Write-Output "--------------------------------"
Write-Output "Enable Mixed mode authentication"
Write-Output "--------------------------------"
write-output "Current Login Mode: $($sqlServer.Settings.LoginMode)"
if ($($sqlServer.Settings.LoginMode) -eq [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed)
{
    write-output "Mixed Mode Authentication already enabled."   
}
else{
    $sqlServer.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed
    write-output "New Login Mode: $($sqlServer.Settings.LoginMode)"
}

Write-Output "--------------------------------"
Write-Output "Add/Update sql user(s)"
Write-Output "--------------------------------"
if (!$sqlServer.Logins.Item('sa') -and $sqlServer.Logins.Item($adminUser))
{
    write-output "$adminUser already exists."
}
elseif ($sqlServer.Logins.Item('sa')){
    write-output "Enabling 'sa' user"
    $sqlServer.Logins.Item('sa').Enable()
    write-output "Renaming 'sa' user"
    $sqlServer.Logins.Item('sa').Rename($adminUser)
    write-output "Setting 'sa' user password"
    $sqlServer.Logins.Item($adminUser).ChangePassword($adminPass)
}
elseif (!$sqlServer.Logins.Item('sa')){
    write-error "ERR: sa user not found...."
}

$query = "sp_configure 'show advanced options', 1;  
GO  
RECONFIGURE;  
GO  
sp_configure 'clr enabled', 1;  
GO  
RECONFIGURE;  
GO"
Invoke-Sqlcmd -Query $query -ServerInstance "$hostname\mssqlserver"
