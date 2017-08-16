# AzureArtifacts

these are mostly useful from a devtestlab automated run of interactive tests

## windows-changescreenresolution

adds the [changescreenresolution.exe](https://github.com/mikedouglasdev/changescreenresolution) tool to set the resolution to 1080p when the test agent logs in

## windows-cisco-vpn

runs the [Citrix DNE fix](ftp://files.citrix.com/), [Cisco 5 VPN installer](https://www.cisco.com/c/en/us/support/web/obsolete/security-vpn-client.html) and [registry patch](http://www.firewall.cx/cisco-technical-knowledgebase/cisco-services-tech/1127-cisco-vpn-client-windows-10-install-fix-442-failed-to-enable-virtual-adapter.html) to get Cisco L2TP VPNs working on Windows 8/10
Ensure to replace the sample pcf with a useful one.
