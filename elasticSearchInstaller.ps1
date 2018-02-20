param($targetDir, $fqdn)

# Start output
$scriptName =  $MyInvocation.ScriptName;
$scriptDir = Split-Path $MyInvocation.MyCommand.Path;
$buildTools = (Split-Path $scriptDir);
$computerName = "$env:computername";
Write-Output "-----------------------------------------";
Write-Output "computerName: $computerName";
Write-Output "ScriptName: $scriptName";
Write-Output "ScriptDir: $scriptDir";
Write-Output "BuildTools: $buildTools";

# Initialize
$version = "elasticsearch-5.6.2"
$url = "https://artifacts.elastic.co/downloads/elasticsearch/$version.zip"
$output = "$env:temp\elasticsearch.zip"
$outpath = "$env:temp\"

########################################
#     don't edit beneath this line     #
########################################

# Stop ElasticSearch Service (if it exists)
if (Test-Path $targetDir\ElasticSearch\bin\elasticsearch-service.bat)
{
    Write-Output "`"$targetDir\ElasticSearch\bin\elasticsearch-service.bat`" stop"
    & cmd /c "`"$targetDir\ElasticSearch\bin\elasticsearch-service.bat`" stop"
    #& cmd /c "TASKKILL /f /im java.exe"
    #Start-Sleep -s 10
}
else{
    Write-Output "`"$targetDir\ElasticSearch\bin\elasticsearch-service.bat`" does not exist!"
}

# Download Java http://www.weirdwindowsfixes.com/2017/05/powershell-download-and-install-java.html
$javax64install = ((Invoke-WebRequest –Uri 'https://www.java.com/en/download/manual.jsp').Links | Where-Object { $_.innerHTML -eq "Windows Offline (64-bit)" }).href
$javax64 = "$env:temp\java.exe"
If !((Test-Path($javax64)))
{
    Write-Output "Downloading $javax64install"
    $start_time = Get-Date
    (New-Object System.Net.WebClient).DownloadFile($javax64install, $javax64)
    Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"
    
    # Install Java
    $javax64install = Start-Process -FilePath $javax64 -ArgumentList "/s INSTALL_SILENT=1 STATIC=0 AUTO_UPDATE=0 WEB_JAVA=1 WEB_JAVA_SECURITY_LEVEL=H WEB_ANALYTICS=0 EULA=0 REBOOT=0 NOSTARTMENU=0 SPONSORS=0 /L $Logfile" -Wait -Verbose -PassThru
	Start-Sleep -s 35
	if ($javax64install.ExitCode -eq 0) {
		Write-Output "Successfully Installed Java RE X64"
	}
	else {
		Write-Error "Java 64 bit installer exited with exit code $($javax64install.ExitCode)"
	}
}

# Download ElasticSearch
Write-Output "------------------------------------------"
Write-Output "Downloading $url"
$start_time = Get-Date
(New-Object System.Net.WebClient).DownloadFile($url, $output)
Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"

# Unzip ElasticSearch
Write-Output "------------------------------------------"
Write-Output "Unzipping $output"
$start_time = Get-Date
if (Test-Path "$outpath\$version")
{
    Remove-Item "$outpath\$version" -force -recurse
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($output, $outpath)
Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"

# Copy ElasticSearch to target directory
Write-Output "------------------------------------------"
Write-Output "Copying $outpath\$version\* to $targetDir\ElasticSearch"
$start_time = Get-Date
if (Test-Path "$targetDir\ElasticSearch")
{
    Remove-Item "$targetDir\ElasticSearch" -force -recurse
} 
Copy-Item $outpath\$version $targetDir\ElasticSearch -force -Recurse
Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"

# Update ElasticSearch config file
Write-Output "------------------------------------------"
Write-Output "Updating $targetDir\ElasticSearch\config\elasticsearch.yml"
$start_time = Get-Date
New-Item "$targetDir\ElasticSearch\config\elasticsearch.yml" -type file -force -value "network.host: 0.0.0.0`r`nhttp.cors.enabled: true`r`nhttp.cors.allow-origin: `"/.*/`"`r`nhttp.cors.allow-credentials: true`r`nhttp.cors.allow-headers: `"X-Requested-With, Content-Type, Content-Length, Authorization`""
Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"

# Install ElasticSearch Service
Write-Output "------------------------------------------"
Write-Output "Installing ElasticSearch Service"
#Write-Output "`"$targetDir\ElasticSearch\bin\elasticsearch-service.bat`" install"
& cmd /c "`"$targetDir\ElasticSearch\bin\elasticsearch-service.bat`" install"

# Automatically start ElasticSearch Service on boot
Write-Output "------------------------------------------"
Write-Output "Setting ElasticSearch Service to start on boot"
Set-Service elasticsearch-service-x64 -startuptype "Automatic"

# Start ElasticSearch Service
Write-Output "------------------------------------------"
Write-Output "Starting ElasticSearch Service"
#Write-Output "`"$targetDir\ElasticSearch\bin\elasticsearch-service.bat`" start"
& cmd /c "`"$targetDir\ElasticSearch\bin\elasticsearch-service.bat`" start"

# Start ElasticSync via API Call
Write-Output "------------------------------------------"
Write-Output "Starting ElasticSync"
$POSTparams = @'
{
 "start":true
}
'@
if (!$fqdn){
    hostname | foreach-object {
        if ($_.Contains("AZ-DEV-LAB")){
            $fqdn = "$_.westeurope.cloudapp.azure.com"
        } else{
            $fqdn = "$_.amcs.local"
        }
    }
}
try{
    Write-Output "Calling http://$fqdn/ElasticSync/syncrequests..."
    Invoke-WebRequest -Uri http://$fqdn/ElasticSync/syncrequests -Method POST -Body $POSTparams -ContentType "application/json"
}
catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Output "EXCEPTION: $ErrorMessage"
}

Write-Output "Adding firewall rule"
& netsh advfirewall firewall add rule name="ElasticSearch" dir=in action=allow protocol=TCP localport=9200
