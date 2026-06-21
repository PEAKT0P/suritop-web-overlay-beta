# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v3

EAPI=8

DESCRIPTION="Security monitoring system: Suricata IDS + ModSecurity WAF + Fail2Ban + iptables dashboard"
HOMEPAGE="https://github.com/denjik/suritop-web"
SRC_URI=""

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="+iptables nat docker +suricata geoip"

RDEPEND="
	net-analyzer/suricata
	net-analyzer/fail2ban
	dev-lang/php:=[pdo,mysql]
	virtual/mysql
	dev-python/pymysql
	www-servers/nginx
	sys-apps/shadow
	sys-apps/coreutils
	geoip? ( dev-libs/geoip )
"
BDEPEND="
	sys-apps/shadow
	sys-apps/coreutils
"

S="${WORKDIR}/${P}"

pkg_setup() {
	getent group stats_collector >/dev/null || groupadd -g 460 stats_collector
	getent passwd stats_collector >/dev/null || useradd -u 460 -g stats_collector -d /var/lib/stats_collector -s /sbin/nologin -c "suritop-web stats collector" stats_collector
}

src_unpack() {
	mkdir -p "${S}"
	cp -r "${FILESDIR}/"* "${S}/" 2>/dev/null || true
}

src_install() {
	exeinto /usr/libexec/suritop-web
	insopts -m0755 -o stats_collector -g stats_collector
	doexe "${S}"/stats_collector.py
	doexe "${S}"/suricata_collector.py
	doexe "${S}"/modsec_collector.py
	doexe "${S}"/geo_fill.py
	doexe "${S}"/utils.py
	insopts -m0644 -o stats_collector -g stats_collector
	doins "${S}"/collector.conf

	insopts -m0755 -o stats_collector -g stats_collector
	doexe "${S}"/suritop.py

	dosym /usr/libexec/suritop-web/suritop.py /usr/bin/suritop

	insopts -m0755 -o root -g root
	doexe "${S}"/iptables_api.py

	insopts -m0644 -o stats_collector -g stats_collector
	doins "${S}"/suritop_config.py

	insopts -m0755
	exeinto /usr/libexec/suritop-web
	doexe "${S}"/suritop-patch.py

	diropts -m0755 -o root -g root
	dodir /var/www/suritop-web/htdocs/attackmap
	dodir /var/www/suritop-web/htdocs/iptables

	insinto /var/www/suritop-web/htdocs
	insopts -m0644
	doins "${S}"/admin_stats.php
	newins "${S}"/root-index.php index.php
	newins "${S}"/root-config.php config.php

	insinto /var/www/suritop-web/htdocs/attackmap
	doins "${S}"/index.php
	doins "${S}"/config.php

	insinto /var/www/suritop-web/htdocs/iptables
	doins "${S}"/api.php
	newins "${S}"/iptables_index.html index.html

	insopts -m0644
	insinto /etc/suritop-web
	doins "${S}"/nginx-vhost.conf
	doins "${S}"/collector.conf
	doins "${S}"/suricata.yaml
	doins "${S}"/drop.conf
	doins "${S}"/classification.config
	doins "${S}"/reference.config
	doins "${S}"/threshold.config
	doins "${S}"/disable.conf

	diropts -m0755 -o root -g root
	dodir /etc/suritop-web/rules
	insinto /etc/suritop-web/rules
	insopts -m0644
	doins "${S}"/local.rules

	insinto /etc/fail2ban/jail.d
	insopts -m0644
	doins "${S}"/fail2ban-suritop.local

	insinto /etc/conf.d
	insopts -m0644
	newins "${S}"/suritop-web.conf suritop-web

	newinitd "${S}"/suritop-stats.initd suritop-stats
	newinitd "${S}"/suritop-suri.initd suritop-suri
	newinitd "${S}"/suritop-waf.initd suritop-waf
	newinitd "${S}"/suritop-iptables.initd suritop-iptables

	if use iptables; then
		newinitd "${S}"/suritop-iptables-setup suritop-iptables-setup
	fi

	insinto /etc/logrotate.d
	newins "${S}"/suritop-web.logrotate suritop-web

	dodir /usr/share/suritop-web
	insinto /usr/share/suritop-web
	newins "${S}"/schema.sql schema.sql

	dosbin "${S}"/suritop-setup.sh

	diropts -m0755 -o stats_collector -g stats_collector
	keepdir /var/lib/stats_collector

	dodir /etc/nginx/vhosts.d

	dodoc "${S}"/README.gentoo
}

pkg_postinst() {
	einfo ""
	einfo "suritop-web installed successfully!"
	einfo ""

	if [[ ! -f "${EROOT}/etc/suritop-web/.configured" ]]; then
		einfo "First installation detected."
		einfo ""
		einfo "Run interactive setup:"
		einfo "  suritop-setup.sh"
		einfo ""
		einfo "Or configure manually:"
		einfo "  1. Edit /etc/conf.d/suritop-web"
		einfo "  2. Import schema: mysql -u root < /usr/share/suritop-web/schema.sql"
		einfo "  3. Enable services: rc-update add suritop-stats default"
		einfo "  4. Start: rc-service suritop-stats start"
		einfo ""
	else
		einfo "Configuration found at /etc/conf.d/suritop-web"
		einfo "Re-run config: suritop-setup.sh"
		einfo ""
	fi
}
