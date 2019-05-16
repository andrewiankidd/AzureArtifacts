param(
	[Parameter(Mandatory=$true)]
	[string]$adminPassword,
	
	[Parameter(Mandatory=$false)]
	[string]$domainName = "amcsplatform.local"
)

# Stop script on error
$ErrorActionPreference = "Stop";

# Convert plaintext password to SecureString
$securePassword = ($adminPassword | ConvertTo-SecureString -AsPlainText -Force);

# Create PSCredentials object
$credStore = New-Object System.Management.Automation.PSCredential("$domainName\$adminUsername", $securePassword);

# default to false
$joined = $false;

# Set up timeout
$startTime = (Get-Date);

Write-Output "Adding Computer to domain"
# Try to add machine to the domain group for 5 minutes
$attempt = 0;
$lastErr = "No Last Error recorded";
while (!$joined -and ( (New-TimeSpan -Start ($startTime) -End (Get-Date)).totalMinutes -lt 5 ) ) {
  try {
    Write-Output "Attempt #$($attempt)";

    # Flush DNS as prep
    Write-Output "IPCONFIG /FLUSHDNS";
    & IPCONFIG /FLUSHDNS;

    Write-Output "NSLOOKUP $domainName";
    & NSLOOKUP $domainName;

    Add-Computer -DomainName "$domainName" -Credential $credStore -LocalCredential $credStore -ErrorAction Stop;
    $joined = $true;
  } catch {
    if ($_.Exception.Message.Contains("already in that domain")) {
      $joined = $true;
    }
    $lastErr = $_.Exception.Message;
  }
  $attempt++;
}

if (!$joined) {
  Write-Warning "Failed to join domain."
  Write-Error $lastErr;
}


Write-Output "Complete."
