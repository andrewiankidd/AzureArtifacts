#!/usr/bin/env bash
# shellcheck disable=SC1090
# Install with this command (from your Linux machine):
#
# curl -sSL https://raw.githubusercontent.com/andrewiankidd/AzureArtifacts/master/webmin.sh | bash
wget http://prdownloads.sourceforge.net/webadmin/webmin_1.881_all.deb
sudo apt-get install -y perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python
sudo dpkg --install webmin_1.881_all.deb
