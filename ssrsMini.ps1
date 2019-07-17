param (
    [string]$fqdn,

    [string]$adminUser = "devops",

    [string]$adminPassword,

    [string]$reportUser = "reportsdbuser",

    [string]$reportPass,

    [string]$reportPath = "/",

    [string]$httpUrl = "http://+:80",

    [string]$lcid = "1033"
)

function writeTitle($text) {
     Write-Output "`r`n----------------------------------------------------------------`r`n$($text)`r`n----------------------------------------------------------------"
}

function writeOutput($text) {
    Write-Output "> $($text)"
}

cls
$ErrorActionPreference = "Continue";
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Connect to the instance using SMO
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null;
$sqlServer = new-object ("Microsoft.SqlServer.Management.Smo.Server") ".";

# print some handy vars
writeTitle -text "Script Initialization";
writeOutput "adminUser: $($adminUser)";;
writeOutput "adminPassword: $($adminPassword)"
writeOutput "Instance Name: $($sqlServer.Name)";
writeOutput "Instance Version: $($sqlServer.Version)";

# disable ieESC https://gist.github.com/danielscholl/bbc18540418e17c39a4292ffcdcc95f0
function Disable-ieESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}
Disable-ieESC

# Check for SSRS2017
writeTitle -text "SSRS2017 Installation";
if (Test-Path("C:\Program Files\SSRS\Shared Tools\")) {

    writeOutput "SSRS 2017 already installed!";

} else {
    # download
    writeOutput "Downloading SSRS Installer..."
	Invoke-WebRequest "https://download.microsoft.com/download/E/6/4/E6477A2A-9B58-40F7-8AD6-62BB8491EA78/SQLServerReportingServices.exe" -OutFile "$env:temp\SQLServerReportingServices.exe" -UseBasicParsing;

    # install
    writeOutput "Installing SSRS...";
	Start-Process "$env:temp\SQLServerReportingServices.exe" -ArgumentList '/passive', '/IAcceptLicenseTerms', '/norestart', '/Log reportserver.log', '/InstallFolder="C:\Program Files\SSRS"', '/Edition=Dev' -Wait
}

# Check for $reportUser
writeTitle -text "Windows ReportUser setup ($reportUser)";
if ((Get-LocalUser | Where-Object {$_.Name -eq "$reportUser"}).Length -gt 0) {

    # done!
    writeOutput "Windows User '$reportUser' already exists!";
   
} else {
    writeOutput "Creating '$reportUser'";
	writeOutput "New-LocalUser -Name $reportUser -Description 'SSRS User' -Password (ConvertTo-SecureString $reportPass -AsPlainText -Force) -PasswordNeverExpires -UserMayNotChangePassword;"
	New-LocalUser -Name $reportUser -Description "SSRS User" -Password (ConvertTo-SecureString $reportPass -AsPlainText -Force) -PasswordNeverExpires -UserMayNotChangePassword;
}

# Check for ReportServer database
writeTitle -text "ReportServer Firewall Port";
if((& netsh advfirewall firewall show rule name="SSRS HTTP") | ?{$_.Contains("Allow")}){

     # done
    writeOutput "ReportServer Firewall Port already exists!";

} else {

    # add firewall rule for ssrs
    writeOutput "Creating ReportServer Firewall Port..."
    netsh advfirewall firewall add rule name="SSRS HTTP" dir=in action=allow protocol=TCP localport=80
}

# Check for ReportServer BarCode font
writeTitle -text "Barcode Font Installation";
if (Test-Path "C:\windows\Fonts\code128.ttf")
{
   writeOutput "Font Exists!"
}
else{
    
    $url = "http://github.com/andrewiankidd/AzureArtifacts/raw/master/code128.ttf";
    $file = "$env:temp\code128.ttf";
    $target = "C:\windows\Fonts\code128.ttf";

    writeOutput "Downloading Font";
    Invoke-WebRequest $url -OutFile $file -UseBasicParsing;

    writeOutput "Installing Font";
    copy-item $file $target -Force;

    writeOutput "Registering Font";
    New-ItemProperty -Name $target -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -PropertyType string -Value $File;
}

# Ensure SQL authentication is enabled
writeTitle -text "Verifying SQL Server LoginMode";
if ($sqlServer.Settings.LoginMode -eq [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed) {
       
    writeOutput "SQL Login Mode already enabled.";
} else {

    # Enable mixed auth
    writeOutput "Enabling SQL Login mode...";
    $sqlServer.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed;
    Restart-Service -Force MSSQLSERVER;
}

# Check adminuser
if (!($sqlServer.Logins | ?{$_.Name -eq ($adminUser)})) {

    # Add admin user to sql
    $adminLogin = [Microsoft.SqlServer.Management.Smo.Login]::New($sqlServer, $adminUser);
    $adminLogin.LoginType  = [Microsoft.SqlServer.Management.Smo.LoginType]::SqlLogin;
    $adminLogin.PasswordPolicyEnforced  = $False;
    $adminLogin.Create($adminPassword);

    # Save to server
    $sqlServer.Roles |?{ $_.IsFixedRole -eq $true} | %{ 
        writeOutput "Adding user '$adminUser' to role '$($_.Name)'";
        $_.AddMember($adminUser) 
    };
    Restart-Service -Force MSSQLSERVER;
}

# Configure the SSRS intallation
writeTitle -text "Connecting to SSRS ReportService";
writeOutput "Getting WMI object..."
$rsConfig = Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v14\Admin" -class MSReportServer_ConfigurationSetting

# Check for ReportServer database
writeTitle -text "SSRS2017 ReportServer Database";
if($sqlServer.Databases["ReportServer"]) {

    # done
    writeOutput "ReportServer Database already exists!";

} else {

    # create database
    writeOutput "Generating ReportServer Database...";
    $GenerateDatabaseCreationScript = ($rsConfig.GenerateDatabaseCreationScript("ReportServer", $lcid, $false)).Script;

    writeOutput "Writing ReportServer Database..."
    Invoke-Sqlcmd -Query $GenerateDatabaseCreationScript -U $adminUser -P $adminPassword;

    writeOutput "Setting RSS Database..."
    $rsConfig.SetDatabaseConnection($env:computername, "ReportServer", 1, $adminUser, $adminPassword)
}

# URL Bindings
writeTitle -text "URL Bindings ($httpUrl)";
if (($rsConfig.ListReservedURLs() | ? {$_.UrlString -like ("$($httpUrl.Replace('+','*'))") }).length -gt 0) {

    # done!
    writeOutput "URL Binding '$httpUrl' already exists!";

} else {

    # define virtual directories
    $vDirectories = @{
        "ReportServerWebService" = "ReportServer"
        "ReportServerWebApp" = "Reports"
    };

    # process
    foreach ($kv in $vDirectories.GetEnumerator())
    {
        $key = $kv.Name;
        $value = $kv.Value;
        writeOutput "Adding URL: $($httpUrl)/$value => $key";

        $rsConfig.SetVirtualDirectory($key, $value, $lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR SetVirtualDirectory: FAIL: $($_.Error)" } else{ writeOutput "SetVirtualDirectory: OK"; }}
        $rsConfig.ReserveURL($key, "$httpUrl", $lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR ReserveURL: FAIL: $($_.Error)" } else{ writeOutput "ReserveURL: OK"; }}
    }
}

writeTitle -text "Basic Auth support";
$fileLocation = "C:\Program Files\SSRS\SSRS\ReportServer\rsreportserver.config";
$fileContents = [System.IO.File]::ReadAllText($FileLocation);
if ($fileContents.Contains('<AuthenticationTypes><RSWindowsBasic/></AuthenticationTypes>')) {

    # done!
    writeOutput "Basic Auth already setup!";

} else {

    writeOutput "Locating existing configuration..."; 
    
    # find auth tag
    [regex]$regex = "(<Authentication>)([\s\S]*?)(<\/Authentication>)";
    $m = $regex.Matches([System.IO.File]::ReadAllText($FileLocation));

    # replace
    $replace = "<Authentication><AuthenticationTypes><RSWindowsBasic/></AuthenticationTypes><RSWindowsExtendedProtectionLevel>Off</RSWindowsExtendedProtectionLevel><RSWindowsExtendedProtectionScenario>Proxy</RSWindowsExtendedProtectionScenario></Authentication>";
    
    # save
    writeOutput "Saving changes..."; 
    $fileContents.replace($m[0], $replace) | Set-Content $FileLocation;
}

writeTitle -text "Web ReportUser setup ($reportUser)";
if (1 -eq 2) {

    # done!
     writeOutput "Web User '$reportUser' already exists!";
} else {

    # Connect to (localhost) SSRS service
    $ssrs = $null;
    $start = Get-Date;
   
    writeOutput "Connecting to local report service...";
    while ((!$ssrs) -and ((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds -lt 300)) {

        # Try for FIVE minutes
    	writeOutput "$((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds) Trying to connect...";
        $ssrs = New-WebServiceProxy -Uri "http://localhost/ReportServer/ReportService2010.asmx?wsdl" -Credential (New-Object System.Management.Automation.PSCredential ("$adminUser", (ConvertTo-SecureString "$adminPassword" -AsPlainText -Force))) -ErrorAction SilentlyContinue;
    }

    if (!$ssrs) {
    	Write-Error "Could not connect to SSRS";
    }
    else {
         writeOutput "Connected!";
    }

    $namespace = $ssrs.GetType().Namespace;
    $changesMade = $false;
    $policies = $null;
    
    # Get Root Dir Policies
    writeOutput "Retreiving existing server Policies...";
    $policies = $ssrs.GetPolicies($reportPath, [ref]$true)

    # Get new local user
    $reportUser = "$($env:ComputerName)\$($reportUser)"

    writeOutput "Checking Policies for '$reportUser'";
    # Check if user is already assigned to Policy
    if (!($policies.GroupUserName -contains "$reportUser")) {

        # Build new policy object
	    $policy = New-Object -TypeName ($namespace + '.Policy');
	    $policy.GroupUserName = $reportUser;
	    $policy.Roles = @();
	    $policies += $policy;
	    $changesMade = $true;

    } else {

        # Obtain existing policy
        $policy = $policies.Where({$_.GroupUserName.Contains($reportUser)}, 1);
    }

    $roles = $policy.Roles;
    $requiredRoles = @("Browser", "Content Manager", "My Reports", "Publisher", "Report Builder");
    $requiredRoles | % {
	    if (($roles.Name -contains $_) -eq $false)
	    {
		    #A role for the policy needs to added
		    writeOutput "Policy doesn't contain specified role ($($_)). Adding.";
		    $role = New-Object -TypeName ($namespace + '.Role');
		    $role.Name = $_;
		    $policy.Roles += $role;
		    $changesMade = $true;
	    }
	    else{
		    writeOutput "Policy already contains specified role ($($_)).";
	    }
    }

    if ($changesMade)
    {
	    writeOutput "Saving changes to SSRS.";
	    $ssrs.SetPolicies($reportPath, $policies);
    }
}

# restart services
writeTitle -text "Finalizing";
writeOutput "Restarting SSRS service..."
$rsConfig.SetServiceState($false, $false, $false) | Out-Null
$rsConfig.SetServiceState($true, $true, $true) | Out-Null
Restart-Service -SERVICENAME SQLServerReportingServices
Start-Service -SERVICENAME SQLServerReportingServices

# done
writeTitle -text "Done!";
return;
	
