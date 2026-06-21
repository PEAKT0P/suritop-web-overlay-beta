#!/bin/bash
# suritop-setup.sh — Interactive setup script for suritop-web
# Part of net-analyzer/suritop-web Gentoo overlay
# Run: suritop-setup.sh

set -e

CONFIGURED_FLAG="/etc/suritop-web/.configured"
CONF_FILE="/etc/conf.d/suritop-web"
COLLECTOR_CONF="/etc/suritop-web/collector.conf"
SURICATA_YAML="/etc/suritop-web/suricata.yaml"

info()  { echo -e " \033[1;32m*\033[0m $*"; }
warn()  { echo -e " \033[1;33m*\033[0m $*"; }
error() { echo -e " \033[1;31m*\033[0m $*"; }

if [[ ${EUID} -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

echo ""
info "suritop-web Interactive Configuration"
info "======================================"
echo ""

DEFAULT_IF=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{print $5}' | head -1)
DEFAULT_IF=${DEFAULT_IF:-eth0}
DEFAULT_IP=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1)
if [[ -z "${DEFAULT_IP}" ]]; then
    DEFAULT_IP=$(ip -4 addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -1)
fi
if [[ -z "${DEFAULT_IP}" ]]; then
    DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
DEFAULT_IP=${DEFAULT_IP:-127.0.0.1}
DEFAULT_SSH=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
DEFAULT_SSH=${DEFAULT_SSH:-22}

info "Detected network:"
info "  Interface: ${DEFAULT_IF}"
info "  Server IP: ${DEFAULT_IP}"
info "  SSH Port:  ${DEFAULT_SSH}"
echo ""

sed -i "s|@@SERVER_IP@@|${DEFAULT_IP}|g" "${CONF_FILE}" 2>/dev/null
sed -i "s|@@NET_INTERFACE@@|${DEFAULT_IF}|g" "${CONF_FILE}" 2>/dev/null
sed -i "s|@@SSH_PORT@@|${DEFAULT_SSH}|g" "${CONF_FILE}" 2>/dev/null
sed -i "s|@@SERVER_IP@@|${DEFAULT_IP}|g" "${COLLECTOR_CONF}" 2>/dev/null
sed -i "s|@@NET_INTERFACE@@|${DEFAULT_IF}|g" "${COLLECTOR_CONF}" 2>/dev/null
sed -i "s|@@SERVER_IP@@|${DEFAULT_IP}|g" "${SURICATA_YAML}" 2>/dev/null
sed -i "s|@@NET_INTERFACE@@|${DEFAULT_IF}|g" "${SURICATA_YAML}" 2>/dev/null
info "Config files templated with detected values"

info "Setup nginx with basic auth (admin:admin)? [Y/n]"
read -r REPLY
if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
    cp /etc/suritop-web/nginx-vhost.conf /etc/nginx/vhosts.d/suritop-web.conf
    info "Nginx vhost installed"

    if command -v python3 >/dev/null 2>&1; then
        HASH=$(python3 -c "
import subprocess, base64, os
salt = base64.b64encode(os.urandom(16)).decode()
r = subprocess.run(['openssl', 'passwd', '-6', '-salt', salt, 'admin'], capture_output=True, text=True)
print(f'admin:{r.stdout.strip()}')
" 2>/dev/null)
        if [[ -n "${HASH}" ]]; then
            echo "${HASH}" > /etc/nginx/.htpasswd
            info "Basic auth created: admin / admin"
        fi
    fi
    echo ""
fi

info "Setup database (import schema + create users)? [Y/n]"
read -r REPLY
if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
    if ! rc-service mysql status >/dev/null 2>&1; then
        info "Starting MariaDB/MySQL..."
        rc-service mysql start 2>/dev/null
        sleep 2
    fi

    DB_CMD=""
    if command -v mariadb >/dev/null 2>&1; then
        DB_CMD="mariadb"
    elif command -v mysql >/dev/null 2>&1; then
        DB_CMD="mysql"
    fi

    if [[ -n "${DB_CMD}" ]]; then
        DB_OK=0
        DB_OPTS=""
        if ${DB_CMD} -u root -e "SELECT 1" >/dev/null 2>&1; then
            DB_OK=1
            DB_OPTS="-u root"
        fi

        if [[ ${DB_OK} -eq 0 ]]; then
            info "MySQL/MariaDB requires root password."
            info "Enter root password (leave empty if none):"
            read -rs DB_ROOT_PASS
            if [[ -n "${DB_ROOT_PASS}" ]]; then
                if ${DB_CMD} -u root -p"${DB_ROOT_PASS}" -e "SELECT 1" >/dev/null 2>&1; then
                    DB_OK=1
                    DB_OPTS="-u root -p${DB_ROOT_PASS}"
                else
                    warn "Cannot connect with provided password"
                fi
            else
                warn "Cannot connect as root without password"
                warn "Run manually: ${DB_CMD} -u root -p < /usr/share/suritop-web/schema.sql"
            fi
        fi

        if [[ ${DB_OK} -eq 1 ]]; then
            info "Database connected"

            if ${DB_CMD} ${DB_OPTS} < /usr/share/suritop-web/schema.sql 2>/dev/null; then
                info "Schema imported"
            else
                warn "Schema import failed (tables may already exist)"
            fi

            read -rp "Enter password for stats_reader user [suritop_read_2026]: " READER_PASS
            READER_PASS=${READER_PASS:-suritop_read_2026}
            read -rp "Enter password for stats_writer user [suritop_write_2026]: " WRITER_PASS
            WRITER_PASS=${WRITER_PASS:-suritop_write_2026}

            if ${DB_CMD} ${DB_OPTS} -e "
                CREATE USER IF NOT EXISTS 'stats_reader'@'localhost' IDENTIFIED BY '${READER_PASS}';
                GRANT SELECT ON server_stats.* TO 'stats_reader'@'localhost';
                CREATE USER IF NOT EXISTS 'stats_writer'@'localhost' IDENTIFIED BY '${WRITER_PASS}';
                GRANT INSERT,SELECT,DELETE ON server_stats.* TO 'stats_writer'@'localhost';
                FLUSH PRIVILEGES;
            " 2>/dev/null; then
                info "DB users created (stats_reader / stats_writer)"
            else
                warn "DB user creation failed"
            fi
        else
            warn "Cannot connect to database as root"
            warn "Run manually: ${DB_CMD} -u root -p < /usr/share/suritop-web/schema.sql"
        fi
    else
        warn "mariadb/mysql not found — skip database setup"
    fi
    echo ""
fi

info "Install suricata configs? [Y/n]"
read -r REPLY
if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
    if [[ -d /etc/suricata ]]; then
        for f in suricata.yaml classification.config reference.config threshold.config; do
            cp "/etc/suritop-web/${f}" /etc/suricata/ 2>/dev/null
        done
        cp /etc/suritop-web/rules/local.rules /etc/suricata/rules/ 2>/dev/null
        info "Suricata configs installed"
    else
        warn "/etc/suricata not found — skipping"
    fi
    echo ""
fi

info "Setup fail2ban jails? [Y/n]"
read -r REPLY
if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
    if [[ -d /etc/fail2ban/jail.d ]]; then
        cp /etc/fail2ban/jail.d/fail2ban-suritop.local /etc/fail2ban/jail.local 2>/dev/null || \
        cp /etc/suritop-web/fail2ban-suritop.local /etc/fail2ban/jail.d/ 2>/dev/null
        info "Fail2ban jails configured"
    else
        warn "/etc/fail2ban/jail.d not found — skipping"
    fi
    echo ""
fi

info "Enable iptables auto-setup on boot? [y/N]"
info "  WARNING: This will REPLACE your current iptables rules!"
info "  Choose N if you have custom firewall (NAT, Docker, port forwarding)"
read -r REPLY
if [[ "${REPLY}" == "y" || "${REPLY}" == "Y" ]]; then
    sed -i 's|^SURITOP_AUTO_IPTABLES=.*|SURITOP_AUTO_IPTABLES="yes"|' "${CONF_FILE}" 2>/dev/null
    rc-update add suritop-iptables-setup default 2>/dev/null
    info "iptables auto-setup ENABLED"
else
    sed -i 's|^SURITOP_AUTO_IPTABLES=.*|SURITOP_AUTO_IPTABLES="no"|' "${CONF_FILE}" 2>/dev/null
    info "iptables auto-setup DISABLED — your existing rules preserved"
fi
echo ""

info "Enable NAT masquerade? [y/N]"
read -r REPLY
if [[ "${REPLY}" == "y" || "${REPLY}" == "Y" ]]; then
    sed -i 's|^SURITOP_NAT_ENABLE=.*|SURITOP_NAT_ENABLE="yes"|' "${CONF_FILE}" 2>/dev/null
    info "NAT masquerade enabled"
fi
echo ""

info "Enable Docker integration (DOCKER-USER chain)? [y/N]"
read -r REPLY
if [[ "${REPLY}" == "y" || "${REPLY}" == "Y" ]]; then
    sed -i 's|^SURITOP_DOCKER_ENABLE=.*|SURITOP_DOCKER_ENABLE="yes"|' "${CONF_FILE}" 2>/dev/null
    info "Docker integration enabled"
fi
echo ""

info "Enable services in default runlevel? [Y/n]"
read -r REPLY
if [[ "${REPLY}" != "n" && "${REPLY}" != "N" ]]; then
    for svc in suritop-stats suritop-suri suritop-waf suritop-iptables iptables-manager fail2ban suricata; do
        rc-update add ${svc} default 2>/dev/null
    done
    rc-update add iptables default 2>/dev/null
    info "Services added to default runlevel"
fi

touch "${CONFIGURED_FLAG}"
echo ""
info "Configuration complete!"
echo ""
info "Start all services:"
info "  rc-service suritop-iptables start"
info "  rc-service suritop-stats start"
info "  rc-service suritop-suri start"
info "  rc-service suritop-waf start"
info "  rc-service suricata start"
info "  rc-service iptables-manager start"
info "  rc-service nginx restart"
info "  rc-service fail2ban restart"
echo ""
info "Login: admin / admin"
echo ""
