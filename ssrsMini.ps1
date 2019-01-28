param ($fqdn, $adminUser, $adminPassword, $reportUser = "reportsdbuser", $reportPass = $null)
cls
$ErrorActionPreference = "Stop";

Write-Output "--------------------------------"
Write-Output "Script Initialization"
Write-Output "--------------------------------"
# Connect to the instance using SMO
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null
$sqlServer = new-object ("Microsoft.SqlServer.Management.Smo.Server") "."
$versionMajor = $sqlServer.VersionMajor
write-output "fqdn: $($fqdn)"
write-output "adminUser: $($adminUser)"
write-output "adminPassword: $($adminPassword)"
write-output "Instance Name: $($sqlServer.Name)"
write-output "Instance Version: $($sqlServer.Version)"
Write-Output "Version Major: $versionMajor"

if(!$sqlServer.Databases["ReportServer"])
{
	if (!(Test-Path("$env:temp\SQLServerReportingServices.exe")))
	{
		write-output "SQL Server 2017 and up does not come bundled with SSRS. Downloading SSRS Installer..."
		$url = "https://download.microsoft.com/download/E/6/4/E6477A2A-9B58-40F7-8AD6-62BB8491EA78/SQLServerReportingServices.exe"
		Invoke-WebRequest $url -OutFile "$env:temp\SQLServerReportingServices.exe" -UseBasicParsing
	}
    
    if (!(Test-Path("C:\Program Files\SSRS\Shared Tools\")))
    {
        Write-Output "Installing SSRS";
		Start-Process "$env:temp\SQLServerReportingServices.exe" -ArgumentList '/passive', '/IAcceptLicenseTerms', '/norestart', '/Log reportserver.log', '/InstallFolder="C:\Program Files\SSRS"', '/Edition=Dev' -Wait
	}

    $httpUrl = "http://+:80/"
    $lcid = 1033 # for english

    Write-Output "--------------------------------"
    Write-Output "Enable SSRS"
    Write-Output "--------------------------------"
    Write-Output "Getting WMI object..."
    $rsConfig = Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v14\Admin" -class MSReportServer_ConfigurationSetting

    # URL Bindings
    $length = $rsConfig.ListReservedURLs().Length;
    if ($length -gt 0)
    {
        Write-Output "Removing Existing Bindings..."
        $rsConfig.ListReservedURLs() | ForEach-Object{
            For ($i=0; $i -lt $length; $i++) {
                Write-Output "Removing URL Binding $($_.Application[$i]), $($_.UrlString[$i])";
                $rsConfig.RemoveURL($_.Application[$i], $_.UrlString[$i], $lcid) | Out-Null
            }
        }

        $length = $rsConfig.ListReservedURLs().Length
        Write-Output "URL Bindings: $length";
        if ($length -gt 0)
        {
            Write-Error "ERR: bindings should be empty:";
            $rsConfig.ListReservedURLs() | ForEach-Object{Write-Output $_}
            exit;
        }
    }

    Write-Output "Setting URL(s)..."
    # SQL 2014 and newer expect 'ReportServerWebApp'
    # SQL 2012 and lower expect 'ReportManager'
    # https://docs.microsoft.com/en-us/sql/reporting-services/breaking-changes-in-sql-server-reporting-services-in-sql-server-2016
    if ([int]$versionMajor -ge 12)
    {
        $vDirectories = @{
            "ReportServerWebService" = "ReportServer"
            "ReportServerWebApp" = "Reports"
        };
    }
    else{
        $vDirectories = @{
            "ReportServerWebService" = "ReportServer"
            "ReportManager" = "Reports"
        };
    }

    foreach ($kv in $vDirectories.GetEnumerator())
    {
        $key = $kv.Name;
        $value = $kv.Value;
        Write-Output "Processing $key, $value"
        Write-Output "HTTP: $httpUrl"

        $rsConfig.SetVirtualDirectory($key,$value,$lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR SetVirtualDirectory: FAIL: $($_.Error)" } else{ Write-Output "SetVirtualDirectory: OK"; }}
        $rsConfig.ReserveURL($key, "$httpUrl", $lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR ReserveURL: FAIL: $($_.Error)" } else{ Write-Output "ReserveURL: OK"; }}
    }

    $secpasswd = ConvertTo-SecureString "$adminUser" -AsPlainText -Force
    $dbCred = New-Object System.Management.Automation.PSCredential ("$adminPassword", $secpasswd)

    Write-Output "Adding $adminUser to dbcreator"
    $query = "EXEC master..sp_addsrvrolemember @loginame = N'$adminUser', @rolename = N'dbcreator'";
    Invoke-Sqlcmd -Query $query -U $adminUser -P $adminPassword

    Write-Output "Generating RSS Database..."
    $result = $rsConfig.GenerateDatabaseCreationScript("ReportServer", $lcid, $false)
    $query = $result.Script
    Write-Output "Writing RSS Database..."
    Invoke-Sqlcmd -Query $query -U $adminUser -P $adminPassword
    Write-Output "Setting RSS Database..."
    $rsConfig.SetDatabaseConnection($env:computername, "ReportServer", 1, $adminUser, $adminPassword)
    
    Write-Output "Opening firewall ports..."
    netsh advfirewall firewall add rule name="SSRS HTTP" dir=in action=allow protocol=TCP localport=80
    
    Write-Output "Switching to basic auth...";
    $fileLocation = "C:\Program Files\SSRS\SSRS\ReportServer\rsreportserver.config";
    [regex]$regex = "(<Authentication>)([\s\S]*?)(<\/Authentication>)";
    $m=$regex.Matches([System.IO.File]::ReadAllText($FileLocation));
    $replace = "<Authentication><AuthenticationTypes><RSWindowsBasic/></AuthenticationTypes><RSWindowsExtendedProtectionLevel>Off</RSWindowsExtendedProtectionLevel><RSWindowsExtendedProtectionScenario>Proxy</RSWindowsExtendedProtectionScenario></Authentication>";
    [System.IO.File]::ReadAllText($FileLocation).replace($m[0], $replace) | Set-Content $FileLocation;

    Write-Output "Restarting SSRS service..."
    $rsConfig.SetServiceState($false, $false, $false) | Out-Null
    $rsConfig.SetServiceState($true, $true, $true) | Out-Null
    Restart-Service -SERVICENAME SQLServerReportingServices
    Start-Service -SERVICENAME SQLServerReportingServices
}
else{
    Write-Output "Reporting already set up"
}

if (!(Test-Path "C:\windows\Fonts\code128.ttf"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $url = "http://github.com/andrewiankidd/AzureArtifacts/raw/master/code128.ttf";
    $file = "$env:temp\code128.ttf";
    $target = "C:\windows\Fonts\code128.ttf"

    Write-Output "Downloading Font"
    Invoke-WebRequest $url -OutFile $file -UseBasicParsing

    Write-Output "Installing Font"
    copy-item $file $target -Force;

    Write-Output "Registering Font"
    New-ItemProperty -Name $target -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -PropertyType string -Value $File
}
else{
    Write-Output "Font Exists!"
}

if ($reportUser -ne $null)
{
    # Create local user for SSRS
    if (!((Get-LocalUser | Where-Object {$_.Name -eq "$reportUser"}).Length -gt 0))
    {
        Write-Output "Creating $reportUser";
	    if ($reportPass -ne $null)
	    {
		    write-output "New-LocalUser -Name $reportUser -Description 'SSRS User' -Password (ConvertTo-SecureString $reportPass -AsPlainText -Force) -PasswordNeverExpires -UserMayNotChangePassword;"
		    New-LocalUser -Name $reportUser -Description "SSRS User" -Password (ConvertTo-SecureString $reportPass -AsPlainText -Force) -PasswordNeverExpires -UserMayNotChangePassword;
	    }
        else{
		    New-LocalUser -Name $reportUser -Description "SSRS User" -NoPassword
	    }
    } else{
        Write-Output "User $reportUser already exists";
    }
    
    # Connect to (localhost) SSRS service
    $ssrs = $null;
    $start = Get-Date
    # Try for FIVE minutes
    Write-Output "New-WebServiceProxy -Uri `"http://localhost/ReportServer/ReportService2010.asmx?wsdl`" -Credential (New-Object System.Management.Automation.PSCredential (`"$adminUser`", (ConvertTo-SecureString `"$adminPassword`" -AsPlainText -Force)))";
    while ((!$ssrs) -and ((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds -lt 300)) {
        $ssrs = New-WebServiceProxy -Uri "http://localhost/ReportServer/ReportService2010.asmx?wsdl" -Credential (New-Object System.Management.Automation.PSCredential ("$adminUser", (ConvertTo-SecureString "$adminPassword" -AsPlainText -Force))) -ErrorAction SilentlyContinue;
    }
    
    $namespace = $ssrs.GetType().Namespace;
    $changesMade = $false;
    $policies = $null;
    
    # Get Root Dir Policies
    $policies = $ssrs.GetPolicies('/', [ref]$true)

    # Get new local user
    $reportUser = "$($env:ComputerName)\$($reportUser)"

    # Check if user is already assigned to Policy
    if (!($policies.GroupUserName -contains "$reportUser"))
    {
	$policy = New-Object -TypeName ($namespace + '.Policy');
	$policy.GroupUserName = $reportUser;
	$policy.Roles = @();
	$policies += $policy;
	$changesMade = $true;
    }

    $roles = $policy.Roles;
    $requiredRoles = @("Browser", "Content Manager", "My Reports", "Publisher", "Report Builder")
    $requiredRoles | % {
	if (($roles.Name -contains $_) -eq $false)
	{
		#A role for the policy needs to added
		Write-Output "Policy doesn't contain specified role ($($_)). Adding.";
		$role = New-Object -TypeName ($namespace + '.Role');
		$role.Name = $_;
		$policy.Roles += $role;
		$changesMade = $true;
	}
	else{
		Write-Output "Policy already contains specified role ($($_)).";
	}
    }

    if ($changesMade)
    {
	Write-Output "Saving changes to SSRS.";
	$ssrs.SetPolicies('/', $policies);
    }
}
