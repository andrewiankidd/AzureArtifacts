#!/usr/bin/env bash
# shellcheck disable=SC1090
wget http://prdownloads.sourceforge.net/webadmin/webmin_1.881_all.deb
sudo apt-get install -y perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python
sudo dpkg --install webmin_1.881_all.deb
