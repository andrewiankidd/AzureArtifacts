param ($fqdn, $adminUser, $adminPassword)
cls

Write-Output "--------------------------------"
Write-Output "Script Initialization"
Write-Output "--------------------------------"
# Connect to the instance using SMO
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null
$sqlServer = new-object ("Microsoft.SqlServer.Management.Smo.Server") "."
$versionMajor = $sqlServer.VersionMajor
write-output "Instance Name: $($sqlServer.Name)"
write-output "Instance Version: $($sqlServer.Version)"
Write-Output "Version Major: $versionMajor"

if(!$sqlServer.Databases["ReportServer"] -Or (1 -eq 1)) #debug
{
    Write-Output "--------------------------------"
    Write-Output "SSL Setup"
    Write-Output "--------------------------------"
    $cert = (Get-ChildItem -path cert:\localmachine\my | Where {$_.subject -contains $env:computername });
    if (!$cert)
    {
        Write-Output "Couldn't find valid SSL Cert, Creating new Self-Signed cert"
        $cert = (New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $fqdn)
    }
    $cert = $cert[0]
    $certhash = ($cert | select -ExpandProperty thumbprint).tolower();
    $sslPort = 443
    $httpUrl = "http://$($fqdn):80/"
    $sslUrl = "https://$($fqdn):443/"
    $lcid = 1033 # for english

    # Trust Cert
    Write-Output "--------------------------------"
    Write-Output "Adding SSL Cert to trust list..."
    Write-Output "--------------------------------"
    $DestStore = New-Object  -TypeName System.Security.Cryptography.X509Certificates.X509Store  -ArgumentList "root", "LocalMachine"
    $DestStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $DestStore.Add($cert)
    $DestStore.Close();

    Write-Output "--------------------------------"
    Write-Output "Enable SSRS"
    Write-Output "--------------------------------"
    Write-Output "Getting WMI object..."
    $wmiName = (Get-WmiObject -namespace root\Microsoft\SqlServer\ReportServer  -class __Namespace).Name
    $rsConfig = Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer\$wmiName\v$versionMajor\Admin" -class MSReportServer_ConfigurationSetting

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

    ## SSL Bindings
    $length = $rsConfig.ListSSLCertificateBindings($lcid).Length;
    if ($length -gt 0)
    {
        Write-Output "Removing Existing Cert Bindings..."

        $rsConfig.ListSSLCertificateBindings($lcid) | ForEach-Object{
            For ($i=0; $i -lt $length; $i++) {
                Write-Output "Removing Cert Binding $($_.Application[$i]), $($_.CertificateHash[$i]), $($_.IPAddress[$i]), $($_.Port[$i]), $lcid";
                $rsConfig.RemoveSSLCertificateBindings($_.Application[$i], $_.CertificateHash[$i], $_.IPAddress[$i], $_.Port[$i], $lcid) | Out-Null
            }
        }

        $length = $rsConfig.ListSSLCertificateBindings($lcid).Length
        Write-Output "Cert Bindings: $length";
        if ($length -gt 0)
        {
            Write-Error "ERR: bindings should be empty:";
            $rsConfig.ListSSLCertificateBindings($lcid) | ForEach-Object{Write-Output $_}
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
        Write-Output "HTTPS: $sslUrl"

        $rsConfig.SetVirtualDirectory($key,$value,$lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR SetVirtualDirectory: FAIL: $($_.Error)" } else{ Write-Output "SetVirtualDirectory: OK"; }}
        $rsConfig.ReserveURL($key, "$httpUrl", $lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR ReserveURL: FAIL: $($_.Error)" } else{ Write-Output "ReserveURL: OK"; }}
        $rsConfig.ReserveURL($key, "$sslUrl", $lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR ReserveHTTPSURL: FAIL: $($_.Error)" } else{ Write-Output "ReserveHTTPSURL: OK"; }}
        $rsConfig.CreateSSLCertificateBinding($key, $certHash, "0.0.0.0", $sslPort, $lcid) | ForEach-Object{ if ($_.HRESULT -ne 0) { Write-Error "ERR CreateSSLCertificateBinding: FAIL: $($_.Error)" } else{ Write-Output "CreateSSLCertificateBinding: OK"; }}
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
    $rsConfig.SetDatabaseConnection(".", "ReportServer", 1, $adminUser, $adminPass) | out-null
    
    Write-Output "Opening firewall ports..."
    netsh advfirewall firewall add rule name="SSRS HTTP" dir=in action=allow protocol=TCP localport=80
    netsh advfirewall firewall add rule name="SSRS HTTPS" dir=in action=allow protocol=TCP localport=443

    Write-Output "Restarting SSRS service..."
    $rsConfig.SetServiceState($false, $false, $false) | Out-Null
    $rsConfig.SetServiceState($true, $true, $true) | Out-Null
}
else{
    Write-Output "Reporting already set up"
}
