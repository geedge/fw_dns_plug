#!/bin/sh
DST=${RPM_INSTALL_PREFIX}
mkdir -p ${DST}/plug/business/
touch ${DST}/plug/conflist.inf
mkdir -p ${DST}/tsgconf/
touch ${DST}/tsgconf/main.conf
if [[ -z `grep -rn 'fw_dns_plug.inf' ${DST}/plug/conflist.inf` ]];then
	sed -i '/\[business\]/a\./plug/business/fw_dns_plug/fw_dns_plug.inf' ${DST}/plug/conflist.inf
fi
if [[ -z `grep -rn '\[DNS_PLUG\]' ${DST}/tsgconf/main.conf` ]];then
	sed -i '1i\\[DNS_PLUG\]' ${DST}/tsgconf/main.conf
	sed -i '/\[DNS_PLUG\]/a\LOG_LEVEL=30' ${DST}/tsgconf/main.conf
	sed -i '/\[DNS_PLUG\]/a\LOG_PATH=./tsglog/fw_dns_plug/fw_dns_plug' ${DST}/tsgconf/main.conf
fi
