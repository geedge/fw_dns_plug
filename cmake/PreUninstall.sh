#!/bin/sh
if [ $1 == 0 ]; then
	DST=${RPM_INSTALL_PREFIX}

	mkdir -p ${DST}/plug/business/
	touch ${DST}/plug/conflist.inf
	mkdir -p ${DST}/tsgconf/
	touch ${DST}/tsgconf/main.conf

	sed -i '/fw_dns_plug.inf/d' ${DST}/plug/conflist.inf
	sed -i '/\[DNS_PLUG\]/,+2d' ${DST}/tsgconf/main.conf
fi
