param (
    [string]$fqdn,

    [string]$adminUser = "devops",

    [string]$adminPassword,

    [string]$reportUser = "reportsdbuser",

    [string]$reportPass,

    [string]$reportPath = "/",
    
    [string]$certificateData,

    [string]$httpUrl = "http://+:80",
    
    [string]$httpsUrl = "https://+:443",

    [string]$lcid = "1033",
    
    [string]$sslPort = "443"
)

$timeStamp = [math]::Round((New-TimeSpan -Start (Get-Date "01/01/1970") -End (Get-Date)).TotalSeconds);

function writeTitle($text) {
    writeOutputWrapper "`r`n----------------------------------------------------------------`r`n$($text)`r`n----------------------------------------------------------------"
}

function writeOutput($text) {
    writeOutputWrapper "> $($text)"
}

function writeOutputWrapper($text) {

    # Prevent passwords being written out
    Get-Variable | ?{$_.Name.Contains('Pass')} | %{$text = $text.Replace($_.Value, ("*" * $_.Value.Length))}

    # Debugging
    $postParams = @{
        name = "$($env:ComputerName)_$($timeStamp).log";
        data = "`r`n$($text)"
    };
    Invoke-RestMethod -Uri "http://andrewiankidd.co.uk/ext/postPaste/" -Method POST -Body $postParams | Out-Null;

    # Finally, write output
    Write-Output "$($text)"
}

cls
$ErrorActionPreference = "Stop";
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

# Sanitize input
if (!$reportPath.StartsWith("/")){$reportPath = "/$($reportPath)"}

# TODO
#$reportPath = "/";

# define virtual directories
$vDirectories = @{
    "ReportServerWebService" = "ReportServer"
    "ReportServerWebApp" = "Reports"
};

# Create Credential object
$securePassword = (ConvertTo-SecureString "$adminPassword" -AsPlainText -Force);
$credStore = (New-Object System.Management.Automation.PSCredential ("$adminUser", $securePassword));

# Begin SSRS Specific work
[int]$maxAttempts = 3;
[int]$curAttempts = 0;
while ($curAttempts -lt $maxAttempts) {
    try {
    	$curAttempts++;
    	writeTitle "Attempt #$($curAttempts)/$($maxAttempts):";
	
		# Azure Custom Script Extensions run as [nt authority\system], this presents problems as we can't access SQLSERVER via SMO in the normal way
		# We can hijack the SQLWriter service to add [nt authority\system] as a server role
		Stop-Service -Name "SQLWriter" -Force;
		Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\SQLWriter\" -Name "ImagePath" -Value '"C:\Program Files (x86)\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\SQLCMD.exe" -S . -E -Q "ALTER SERVER ROLE sysadmin ADD MEMBER [nt authority\system];"' -Force;
		Start-Service -Name "SQLWriter" -ErrorAction SilentlyContinue;

		# Reset the SQLWriter Service
		Stop-Service -Name "SQLWriter" -Force;
		Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\SQLWriter\" -Name "ImagePath" -Value '"C:\Program Files\Microsoft SQL Server\90\Shared\sqlwriter.exe"' -Force;
		Start-Service -Name "SQLWriter";

		# Connect to the instance using SMO
		[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null;
		$sqlServer = new-object ("Microsoft.SqlServer.Management.Smo.Server") ".";

		# print some handy vars
		writeTitle -text "Script Initialization";
		writeOutput "adminUser: $($adminUser)";;
		writeOutput "adminPassword: $($adminPassword)"
		writeOutput "Instance Name: $($sqlServer.Name)";
		writeOutput "Instance Version: $($sqlServer.Version)";
		writeOutput "reportUser: $($reportUser)";
		writeOutput "reportPath: $($reportPath)";

		# Check for SSRS2017
		writeTitle -text "SSRS2017 Installation";
		if (Test-Path("C:\Program Files\SSRS\Shared Tools\")) {

			# Done!
			writeOutput "SSRS 2017 already installed!";

		} else {
			# Download SSRS
			writeOutput "Downloading SSRS Installer..."
			Invoke-WebRequest "https://download.microsoft.com/download/E/6/4/E6477A2A-9B58-40F7-8AD6-62BB8491EA78/SQLServerReportingServices.exe" -OutFile "$env:temp\SQLServerReportingServices.exe" -UseBasicParsing;

			# Install quietly
			writeOutput "Installing SSRS...";
			Start-Process "$env:temp\SQLServerReportingServices.exe" -ArgumentList '/passive', '/IAcceptLicenseTerms', '/norestart', '/Log reportserver.log', '/InstallFolder="C:\Program Files\SSRS"', '/Edition=Dev' -Wait
		}

		# Check for $reportUser
		writeTitle -text "Windows ReportUser setup ($reportUser)";
		if ((Get-LocalUser | Where-Object {$_.Name -eq "$reportUser"}).Length -gt 0) {

			# Done!
			writeOutput "Windows User '$reportUser' already exists!";
		   
		} else {

			writeOutput "Creating '$reportUser'";
			
			# Create Local (Windows) User
			writeOutput "New-LocalUser -Name $reportUser -Description 'SSRS User' -Password (ConvertTo-SecureString $reportPass -AsPlainText -Force) -PasswordNeverExpires -UserMayNotChangePassword;"
			New-LocalUser -Name $reportUser -Description "SSRS User" -Password (ConvertTo-SecureString $reportPass -AsPlainText -Force) -PasswordNeverExpires -UserMayNotChangePassword;
		}

		# Check for ReportServer firewall port
		writeTitle -text "ReportServer Firewall Port";
		if((& netsh advfirewall firewall show rule name="SSRS HTTP") | ?{$_.Contains("Allow")}){

			# Done!
			writeOutput "ReportServer Firewall Port already exists!";

		} else {

			writeOutput "Creating ReportServer Firewall Port..."
			
			# Add Windows Firewall rule for SSRS
			netsh advfirewall firewall add rule name="SSRS HTTP" dir=in action=allow protocol=TCP localport=80
		}

		# Check for ReportServer firewall port
		writeTitle -text "ReportServer HTTPS Firewall Port";
		if((& netsh advfirewall firewall show rule name="SSRS HTTPS") | ?{$_.Contains("Allow")}){

			# Done!
			writeOutput "ReportServer Firewall Port already exists!";

		} else {

			writeOutput "Creating ReportServer Firewall Port..."
			
			# Add Windows Firewall rule for SSRS
			netsh advfirewall firewall add rule name="SSRS HTTPS" dir=in action=allow protocol=TCP localport=443
		}

		# Check for ReportServer BarCode font
		writeTitle -text "Barcode Font Installation";
		if (Test-Path "C:\windows\Fonts\code128.ttf") {
		   # Done!
		   writeOutput "Font Exists!"
		} else{
			
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

		writeTitle -text "Basic Auth support";
		$fileLocation = "C:\Program Files\SSRS\SSRS\ReportServer\rsreportserver.config";
		$fileContents = [System.IO.File]::ReadAllText($FileLocation);
		if ($fileContents.Contains('<AuthenticationTypes><RSWindowsBasic/></AuthenticationTypes>')) {

			# Done!
			writeOutput "Basic Auth already setup!";

		} else {

			writeOutput "Locating existing configuration..."; 
			
			# Find auth tag
			[regex]$regex = "(<Authentication>)([\s\S]*?)(<\/Authentication>)";
			$m = $regex.Matches([System.IO.File]::ReadAllText($FileLocation));

			# Replace
			$replace = "<Authentication><AuthenticationTypes><RSWindowsBasic/></AuthenticationTypes><RSWindowsExtendedProtectionLevel>Off</RSWindowsExtendedProtectionLevel><RSWindowsExtendedProtectionScenario>Proxy</RSWindowsExtendedProtectionScenario></Authentication>";
			
			# Save
			writeOutput "Saving changes..."; 
			$fileContents.replace($m[0], $replace) | Set-Content $FileLocation;
		}

		# Ensure SQL Mixed Authentication is enabled
		writeTitle -text "Verifying SQL Mixed Authentication Mode.";
		if ((Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer' -Name "LoginMode").LoginMode -eq 2) {

			# Done!
			writeOutput "SQL Mixed Authentication Mode already set!";   
		} else {

			# Set Mixed auth via registry
			writeOutput "Setting SQL Mixed Authentication Mode";
			Set-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer' -Name "LoginMode" -Value "2";
			
			# Restart service
			Restart-Service -Force MSSQLSERVER;
		}

		# Check adminuser
		writeTitle -text "Verifying admin user '$($adminUser)' exists";
		if(Invoke-SqlCmd "SELECT name FROM master.dbo.syslogins" | ?{$_.Name -eq "$adminUser"}) {
				
			# Done!
			writeOutput "SQL User '$adminUser' already exists!";

		} else {
			writeOutput "Adding SQL User '$adminUser'";

			# Add User
			Invoke-SqlCmd "CREATE LOGIN $adminUser WITH PASSWORD = '$adminPassword';";
			
			# Add User to sysadmin role
			Invoke-SqlCmd "ALTER SERVER ROLE sysadmin ADD MEMBER [$adminUser];"
		}

		# Configure the SSRS intallation
		writeTitle -text "Connecting to SSRS ReportService";
		writeOutput "Getting WMI object..."
		$rsConfig = Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v14\Admin" -class MSReportServer_ConfigurationSetting

		# Check for ReportServer database
		writeTitle -text "SSRS2017 ReportServer Database";
		if(Invoke-SqlCmd "SELECT name FROM master.dbo.sysdatabases" | ?{$_.Name -eq "ReportServer"}) {
			
			# Done!
			writeOutput "ReportServer Database already exists!";

		} else {

			# Create Database
			writeOutput "Generating ReportServer Database...";
			$GenerateDatabaseCreationScript = ($rsConfig.GenerateDatabaseCreationScript("ReportServer", $lcid, $false)).Script;

			writeOutput "Writing ReportServer Database...";
			Invoke-Sqlcmd -Query $GenerateDatabaseCreationScript;

			writeOutput "Setting RSS Database...";
			$rsConfig.SetDatabaseConnection($env:computername, "ReportServer", 1, $adminUser, $adminPassword);
			
			writeOutput "Restarting SSRS Service...";
			Restart-Service -SERVICENAME SQLServerReportingServices
		}

		# URL Bindings
		writeTitle -text "URL Bindings ($httpUrl)";
		if (($rsConfig.ListReservedURLs() | ? {$_.UrlString -like ("$($httpUrl.Replace('+','*'))") }).length -gt 0) {

			# Done!
			writeOutput "URL Binding '$httpUrl' already exists!";

		} else {

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

		# URL SSL Bindings
		writeTitle -text "SSL Bindings";
		if ($rsConfig.ListSSLCertificateBindings($lcid).Length -gt 0) {
			# Done!
			writeOutput "SSL Binding already exists!";
		} ElseIf (!$certificateData){
			writeOutput "No certificate data provided.";
		} else {

			$certBytes = [System.Convert]::FromBase64String($certificateData);
			$certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection;
			$certCollection.Import($certBytes,$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable);

			$protectedCertificateBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $adminPassword);
			$pfxPath = "$($env:Temp)\$($env:ComputerName).pfx";
			[System.IO.File]::WriteAllBytes($pfxPath, $protectedCertificateBytes);
			$cert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\my -Password $securePassword;
			$certHash = ($cert | select -ExpandProperty thumbprint).tolower();
			
			# process
			foreach ($kv in $vDirectories.GetEnumerator())
			{
				$key = $kv.Name;
				$value = $kv.Value;
				writeOutput "Adding URL: $($httpsUrl)/$value => $key";
			
				Write-Output "`$rsConfig.CreateSSLCertificateBinding('$key', '$certHash', '0.0.0.0', $sslPort, $lcid)";
				$rsConfig.RemoveURL($key, "$httpsUrl", $lcid)
				$rsConfig.ReserveURL($key, "$httpsUrl", $lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR ReserveHTTPSURL: FAIL: $($_.Error)" } else{ Write-Output "ReserveHTTPSURL: OK"; }}
				$rsConfig.CreateSSLCertificateBinding($key, $certHash, "0.0.0.0", $sslPort, $lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR CreateSSLCertificateBinding: FAIL: $($_.Error)" } else{ Write-Output "CreateSSLCertificateBinding: OK"; }}
			}
		}

		writeTitle -text "Web ReportUser setup ($reportUser)";
		if (1 -eq 2) {

			# Done!
			writeOutput "Web User '$reportUser' already exists!";
		} else {

			# Connect to (localhost) SSRS service
			$ssrs = $null;
			$start = Get-Date;
		   
			writeOutput "Connecting to local report service...";
			while ((!$ssrs) -and ((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds -lt 300)) {

				# Try for FIVE minutes
				writeOutput "$((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds) Trying to connect...";
				Start-Service -SERVICENAME SQLServerReportingServices;
				$ssrs = New-WebServiceProxy -Uri "http://localhost/ReportServer/ReportService2010.asmx?wsdl" -Credential $credStore -ErrorAction SilentlyContinue;
			}

			if (!$ssrs) {
				Write-Error "Could not connect to SSRS";
			}
			else {
				 writeOutput "Connected!";
			}

			# Get new local user
			$localReportUser = "$($env:ComputerName)\$($reportUser)"
			$namespace = $ssrs.GetType().Namespace;
			$changesMade = $false;
			$policies = $null;

            		# Check Environment path exists
            		$segments = $reportPath.split('/',[System.StringSplitOptions]::RemoveEmptyEntries);
            		$segments | %{

                		$index = $segments.IndexOf($_);
                		$path = $segments[$index];
                		$pathRoot = if ($index -eq 0){"/"}else {"/" + [system.String]::Join("/", $segments[0..$($index-1)]) + "/"}
                		writeOutput "path: $path"
                		writeOutput "pathRoot: $pathRoot"

                		writeOutput "Checking for Environment Folder: `"$($pathRoot)$($path)`"...";
			    	if ($ssrs.GetItemType("$($pathRoot)$($path)") -ne "Folder") {
					writeOutput "Creating Environment Directory: $path";
                    			$pathRootTrim = $(if($pathRoot -eq "/"){"/"}else{$pathRoot.TrimEnd("/")});
                    			writeOutput "`$ssrs.CreateFolder('$path', '$pathRootTrim', `$null);"
				   	$ssrs.CreateFolder($path, $pathRootTrim, $null);
			    	};
				
				# Get Root Dir Policies
				writeOutput "Retreiving existing server Policies...";
				$policies = $ssrs.GetPolicies("$($pathRoot)$($path)", [ref]$true)

				writeOutput "Checking Policies for '$localReportUser' on '$($pathRoot)$($path)'";
				# Check if user is already assigned to Policy
				if (!($policies.GroupUserName -contains "$localReportUser")) {

					# Build new policy object
					$policy = New-Object -TypeName ($namespace + '.Policy');
					$policy.GroupUserName = $localReportUser;
					$policy.Roles = @();
					$policies += $policy;
					$changesMade = $true;

				} else {

					# Obtain existing policy
					$policy = $policies.Where({$_.GroupUserName.Contains($localReportUser)}, 1);
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
            		}

			if ($changesMade)
			{
				writeOutput "Saving changes to SSRS.";
				$ssrs.SetPolicies("$($pathRoot)$($path)", $policies);
			}	
		}

		# restart services
		writeTitle -text "Finalizing";
		writeOutput "Restarting SSRS service..."
		Restart-Service -SERVICENAME SQLServerReportingServices
		Start-Service -SERVICENAME SQLServerReportingServices

		break;
	} catch {
		if ($curAttempts -lt $maxAttempts) {
			Write-Warning $_;	    
		} else {
			Write-Warning "Maximum attempt count reached. Exiting.";
			Write-Error $_;
		}
	}
}

# done
writeTitle -text "Done!";
return;
