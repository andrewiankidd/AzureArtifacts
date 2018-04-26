#!/usr/bin/env bash
# shellcheck disable=SC1090
wget http://prdownloads.sourceforge.net/webadmin/webmin_1.881_all.deb
apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python
dpkg --install webmin_1.881_all.deb
