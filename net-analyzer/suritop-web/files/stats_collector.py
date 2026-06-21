#!/usr/bin/env python3
"""
stats_collector.py v2 — Демон сбора логов блокировок + системных метрик в MySQL
Плюс дублирует все атаки (Nginx, SSH, Nextcloud) в ipt_drops для графиков PHP.
Запускается через OpenRC, работает под пользователем stats_collector
"""

import re
import os
import sys
import time
import signal
import logging
from datetime import datetime
from pathlib import Path
from collections import deque
from utils import LogTailer

# ── Конфигурация ──
from suritop_config import get_config

_cfg = get_config()

LOG_DIR = '/var/log'
NGINX_LOG_DIR = '/var/log/nginx'
STATE_DIR = '/var/lib/stats_collector'
PID_FILE = '/var/run/stats_collector/stats_collector.pid'
DAEMON_LOG = '/var/log/stats_collector.log'

COLLECT_INTERVAL = 30
METRICS_INTERVAL = 60
BATCH_SIZE = 500

NET_INTERFACE = _cfg['net_interface']
NEXTCLOUD_LOG = '/media/nextcloud/nextcloud/nextcloud.log'

MONITORED_FILES = {
    'messages': f'{LOG_DIR}/messages',
    'fail2ban': f'{LOG_DIR}/fail2ban.log',
}

NGINX_ACCESS_LOGS = [
    'ssl_access_denjik_.ru.log',
    'ssl_access_kamchatka360_ru.log',
    'ssl_access_bez-kluchei-rf.log',
    'ssl_access_yana_denjik_ru.log',
    'ssl_access_pnevmo_denjik_ru.log',
    'access.log',
]

RE_IPT_DROP = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+\S+\s+kernel:\s+IPT-DROP:.*'
    r'SRC=([\d.]+)\s+DST=[\d.]+.*?'
    r'PROTO=(\w+).*?DPT=(\d+)'
)
RE_SSH_FAIL = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([\d.]+)'
)
RE_SSH_INVALID = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'Invalid\s+user\s+(\S+)\s+from\s+([\d.]+)'
)
RE_F2B_ACTION = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+[\d:,]+)\s+fail2ban\.\w+\s+\[\d+\]:\s+'
    r'(?:NOTICE|WARNING)\s+\[(\S+)\]\s+(Ban|Unban)\s+([\d.]+)'
)
RE_NGINX_ACCESS = re.compile(
    r'^([\d.]+)\s+-\s+\S*\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d+)\s+\d+\s+"[^"]*"\s+"([^"]*)"'
)
RE_SUSPICIOUS_URI = re.compile(
    r'(?:wp-(?:admin|includes|content|login|config|setup)|'
    r'xmlrpc\.php|\.env|\.git|phpmyadmin|/shell|/webshell|'
    r'eval\(|base64_|etc/passwd|/bin/sh|\.sql|\.bak|'
    r'setup-config|wlwmanifest|wp-cron)',
    re.IGNORECASE
)
RE_BAD_UA = re.compile(
    r'(?:sqlmap|nikto|nmap|masscan|zgrab|censys|shodan|'
    r'dirbuster|gobuster|wfuzz|nuclei|httpx|'
    r'python-requests/|Go-http-client|curl/|wget/|'
    r'Scrapy|Bot.*crawl|spider)',
    re.IGNORECASE
)

ipt_buffer = deque()
f2b_buffer = deque()
nginx_buffer = deque()
ssh_buffer = deque()
nc_auth_buffer = deque()
running = True


def setup_logging():
    logging.basicConfig(
        filename=DAEMON_LOG,
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def get_db():
    try:
        import MySQLdb
        conn = MySQLdb.connect(
            host=_cfg['db_host'], user=_cfg['db_user_w'], passwd=_cfg['db_pass_w'],
            db=_cfg['db_name'], charset='utf8mb4',
            connect_timeout=5
        )
        conn.autocommit(True)
        return conn
    except ImportError:
        import pymysql
        conn = pymysql.connect(
            host=_cfg['db_host'], user=_cfg['db_user_w'], password=_cfg['db_pass_w'],
            database=_cfg['db_name'], charset='utf8mb4',
            connect_timeout=5, autocommit=True
        )
        return conn


def parse_syslog_date(datestr):
    try:
        year = datetime.now().year
        dt = datetime.strptime(f'{year} {datestr}', '%Y %b %d %H:%M:%S')
        return dt
    except Exception:
        return datetime.now()

def parse_nginx_date(datestr):
    try:
        return datetime.strptime(datestr.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
    except Exception:
        return datetime.now()

def parse_f2b_date(datestr):
    try:
        return datetime.strptime(datestr.split(',')[0], '%Y-%m-%d %H:%M:%S')
    except Exception:
        return datetime.now()

def process_messages(lines):
    for line in lines:
        m = RE_IPT_DROP.search(line)
        if m:
            logged_at = parse_syslog_date(m.group(1))
            ipt_buffer.append((
                m.group(2),
                int(m.group(4)),
                m.group(3),
                logged_at
            ))
            continue

        m = RE_SSH_FAIL.search(line)
        if m:
            logged_at = parse_syslog_date(m.group(1))
            ssh_buffer.append((
                m.group(3),
                m.group(2),
                'failed_password',
                logged_at
            ))
            continue

        m = RE_SSH_INVALID.search(line)
        if m:
            logged_at = parse_syslog_date(m.group(1))
            ssh_buffer.append((
                m.group(3),
                m.group(2),
                'invalid_user',
                logged_at
            ))

def process_fail2ban(lines):
    for line in lines:
        m = RE_F2B_ACTION.search(line)
        if m:
            logged_at = parse_f2b_date(m.group(1))
            action = m.group(3).lower()
            f2b_buffer.append((
                action,
                m.group(2),
                m.group(4),
                logged_at
            ))

def process_nginx_access(lines, log_name):
    for line in lines:
        m = RE_NGINX_ACCESS.match(line)
        if m:
            status = int(m.group(5))
            uri = m.group(4)
            user_agent = m.group(6) if m.group(6) else ''

            collect = False
            if status in (403, 429):
                collect = True
            elif status == 404 and RE_SUSPICIOUS_URI.search(uri):
                collect = True
            elif status >= 400 and status < 500 and RE_BAD_UA.search(user_agent):
                collect = True
            elif status >= 500:
                collect = True

            if collect:
                logged_at = parse_nginx_date(m.group(2))
                nginx_buffer.append((
                    m.group(1),
                    m.group(3),
                    uri[:500],
                    status,
                    user_agent[:500],
                    log_name,
                    logged_at
                ))

def process_nextcloud_log(lines):
    import json
    for line in lines:
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        message = entry.get('message', '')
        level = entry.get('level', 0)

        if level < 2:
            continue

        is_auth = False
        event_type = None

        if 'Login failed' in message or 'Failed login' in message:
            is_auth = True
            event_type = 'login_failed'
        elif 'Bruteforce' in message:
            is_auth = True
            event_type = 'bruteforce'
        elif 'Invalid credentials' in message:
            is_auth = True
            event_type = 'invalid_credentials'
        elif 'Throttle' in message.lower() and 'bruteforce' in message.lower():
            is_auth = True
            event_type = 'bruteforce_throttle'

        if is_auth:
            remote = entry.get('remoteAddr', '') or entry.get('remote', '') or ''
            user = entry.get('user', '') or entry.get('uid', '') or ''
            time_str = entry.get('time', '')

            try:
                logged_at = datetime.strptime(time_str[:19], '%Y-%m-%dT%H:%M:%S')
            except Exception:
                logged_at = datetime.now()

            if remote:
                nc_auth_buffer.append((
                    remote[:45],
                    user[:100],
                    event_type,
                    message[:500],
                    logged_at
                ))

def get_cpu_temp():
    for hwmon in Path('/sys/class/hwmon/').glob('hwmon*'):
        for temp_input in hwmon.glob('temp*_input'):
            try:
                val = int(temp_input.read_text().strip())
                if val > 0:
                    return val / 1000.0
            except Exception:
                continue

    for tz in Path('/sys/class/thermal/').glob('thermal_zone*'):
        try:
            val = int((tz / 'temp').read_text().strip())
            if val > 0:
                return val / 1000.0
        except Exception:
            continue
    return None

def get_net_bytes():
    try:
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith(NET_INTERFACE + ':'):
                    parts = line.split(':')[1].split()
                    rx_bytes = int(parts[0])
                    tx_bytes = int(parts[8])
                    return (rx_bytes, tx_bytes)
    except Exception:
        pass
    return None

def get_conntrack_count():
    try:
        val = Path('/proc/sys/net/netfilter/nf_conntrack_count').read_text().strip()
        return int(val)
    except Exception:
        pass
    try:
        val = Path('/proc/sys/net/nf_conntrack_count').read_text().strip()
        return int(val)
    except Exception:
        pass
    return None

def get_load_avg():
    try:
        data = Path('/proc/loadavg').read_text().strip().split()
        return (float(data[0]), float(data[1]), float(data[2]))
    except Exception:
        return None

def get_memory_info():
    try:
        info = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split()
                key = parts[0].rstrip(':')
                val = int(parts[1])
                info[key] = val
                if len(info) >= 4 and all(k in info for k in ['MemTotal', 'MemFree', 'Buffers', 'Cached']):
                    break

        total = info.get('MemTotal', 0)
        free = info.get('MemFree', 0)
        buffers = info.get('Buffers', 0)
        cached = info.get('Cached', 0)
        used = total - free - buffers - cached
        return (round(used / 1024, 1), round(total / 1024, 1))
    except Exception:
        return None

def flush_to_db(conn):
    cur = conn.cursor()
    flushed = 0

    try:
        # 1. IPT drops (Они и так пишутся в ipt_drops)
        if ipt_buffer:
            batch = []
            while ipt_buffer and len(batch) < BATCH_SIZE:
                batch.append(ipt_buffer.popleft())
            if batch:
                cur.executemany(
                    "INSERT INTO ipt_drops (src_ip, dst_port, proto, logged_at) VALUES (%s, %s, %s, %s)",
                    batch
                )
                flushed += len(batch)

        # 2. F2B actions
        if f2b_buffer:
            batch = []
            while f2b_buffer and len(batch) < BATCH_SIZE:
                batch.append(f2b_buffer.popleft())
            if batch:
                cur.executemany(
                    "INSERT INTO f2b_actions (action, jail, src_ip, logged_at) VALUES (%s, %s, %s, %s)",
                    batch
                )
                flushed += len(batch)

        # 3. Nginx blocks (Дублируем в ipt_drops)
        if nginx_buffer:
            batch = []
            while nginx_buffer and len(batch) < BATCH_SIZE:
                batch.append(nginx_buffer.popleft())
            if batch:
                cur.executemany(
                    "INSERT INTO nginx_blocks (src_ip, method, uri, status, user_agent, log_source, logged_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    batch
                )
                # b[0]=src_ip, b[6]=logged_at. Эмулируем dst_port 443, proto TCP
                ipt_batch = [(b[0], 443, 'TCP', b[6]) for b in batch]
                cur.executemany("INSERT INTO ipt_drops (src_ip, dst_port, proto, logged_at) VALUES (%s, %s, %s, %s)", ipt_batch)
                flushed += len(batch)

        # 4. SSH bruteforce (Дублируем в ipt_drops)
        if ssh_buffer:
            batch = []
            while ssh_buffer and len(batch) < BATCH_SIZE:
                batch.append(ssh_buffer.popleft())
            if batch:
                cur.executemany(
                    "INSERT INTO ssh_attacks (src_ip, username, attack_type, logged_at) "
                    "VALUES (%s, %s, %s, %s)",
                    batch
                )
                # b[0]=src_ip, b[3]=logged_at. Эмулируем dst_port 22, proto TCP
                ipt_batch = [(b[0], 22, 'TCP', b[3]) for b in batch]
                cur.executemany("INSERT INTO ipt_drops (src_ip, dst_port, proto, logged_at) VALUES (%s, %s, %s, %s)", ipt_batch)
                flushed += len(batch)

        # 5. Nextcloud auth failures (Дублируем в ipt_drops)
        if nc_auth_buffer:
            batch = []
            while nc_auth_buffer and len(batch) < BATCH_SIZE:
                batch.append(nc_auth_buffer.popleft())
            if batch:
                cur.executemany(
                    "INSERT INTO nc_auth_fails (src_ip, username, event_type, message, logged_at) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    batch
                )
                # b[0]=src_ip, b[4]=logged_at. Эмулируем dst_port 443, proto TCP
                ipt_batch = [(b[0], 443, 'TCP', b[4]) for b in batch]
                cur.executemany("INSERT INTO ipt_drops (src_ip, dst_port, proto, logged_at) VALUES (%s, %s, %s, %s)", ipt_batch)
                flushed += len(batch)

        conn.commit()

    except Exception as e:
        logging.error(f"DB flush error: {e}")
        try:
            conn.rollback()
        except Exception:
            pass

    return flushed

def record_metrics(conn, prev_net):
    cur = conn.cursor()
    try:
        temp = get_cpu_temp()
        if temp is not None:
            cur.execute("INSERT INTO cpu_temp (temp_c) VALUES (%s)", (temp,))

        net = get_net_bytes()
        if net and prev_net:
            rx_delta = net[0] - prev_net[0]
            tx_delta = net[1] - prev_net[1]
            if rx_delta >= 0 and tx_delta >= 0:
                rx_mbps = round(rx_delta / METRICS_INTERVAL / 1024 / 1024, 3)
                tx_mbps = round(tx_delta / METRICS_INTERVAL / 1024 / 1024, 3)
                cur.execute(
                    "INSERT INTO net_traffic (interface, rx_mbytes_s, tx_mbytes_s, rx_bytes, tx_bytes) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (NET_INTERFACE, rx_mbps, tx_mbps, rx_delta, tx_delta)
                )

        ct = get_conntrack_count()
        if ct is not None:
            cur.execute(
                "INSERT INTO conntrack_stats (connections) VALUES (%s)", (ct,)
            )

        load = get_load_avg()
        mem = get_memory_info()
        if load or mem:
            cur.execute(
                "INSERT INTO system_load (load_1m, load_5m, load_15m, ram_used_mb, ram_total_mb) "
                "VALUES (%s, %s, %s, %s, %s)",
                (
                    load[0] if load else None,
                    load[1] if load else None,
                    load[2] if load else None,
                    mem[0] if mem else None,
                    mem[1] if mem else None,
                )
            )

        conn.commit()
    except Exception as e:
        logging.warning(f"Metrics record error: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
    return net

def cleanup_old_data(conn):
    try:
        cur = conn.cursor()
        tables_6m = ['ipt_drops', 'f2b_actions', 'nginx_blocks', 'ssh_attacks', 'nc_auth_fails']
        for table in tables_6m:
            cur.execute(f"DELETE FROM {table} WHERE logged_at < DATE_SUB(NOW(), INTERVAL 6 MONTH)")

        tables_3m = ['cpu_temp', 'net_traffic', 'conntrack_stats', 'system_load']
        for table in tables_3m:
            col = 'recorded_at'
            cur.execute(f"DELETE FROM {table} WHERE {col} < DATE_SUB(NOW(), INTERVAL 3 MONTH)")

        cur.execute("DELETE FROM geoip_cache WHERE cached_at < DATE_SUB(NOW(), INTERVAL 30 DAY)")
        conn.commit()
        logging.info("Old data cleanup done")
    except Exception as e:
        logging.warning(f"Cleanup error: {e}")

def signal_handler(sig, frame):
    global running
    logging.info(f"Received signal {sig}, shutting down...")
    running = False

def main():
    global running

    setup_logging()
    logging.info("Stats collector v2 starting...")

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    os.makedirs(STATE_DIR, exist_ok=True)
    tailers = {}

    for name, path in MONITORED_FILES.items():
        state_file = os.path.join(STATE_DIR, f'{name}.pos')
        tailers[name] = LogTailer(path, state_file)

    nginx_tailers = {}
    for log_name in NGINX_ACCESS_LOGS:
        log_path = os.path.join(NGINX_LOG_DIR, log_name)
        state_file = os.path.join(STATE_DIR, f'nginx_{log_name}.pos')
        nginx_tailers[log_name] = LogTailer(log_path, state_file)

    nc_tailer = None
    if os.path.exists(NEXTCLOUD_LOG):
        nc_tailer = LogTailer(NEXTCLOUD_LOG, os.path.join(STATE_DIR, 'nextcloud.pos'))
        logging.info(f"Monitoring Nextcloud log: {NEXTCLOUD_LOG}")
    else:
        logging.info(f"Nextcloud log not found: {NEXTCLOUD_LOG}, skipping")

    conn = get_db()
    logging.info("Connected to MySQL")

    last_metrics_time = 0
    last_cleanup_time = time.time()
    prev_net = get_net_bytes()
    cycle = 0

    while running:
        try:
            if 'messages' in tailers:
                lines = tailers['messages'].read_new_lines()
                if lines:
                    process_messages(lines)

            if 'fail2ban' in tailers:
                lines = tailers['fail2ban'].read_new_lines()
                if lines:
                    process_fail2ban(lines)

            for log_name, tailer in nginx_tailers.items():
                lines = tailer.read_new_lines()
                if lines:
                    process_nginx_access(lines, log_name)

            if nc_tailer:
                lines = nc_tailer.read_new_lines()
                if lines:
                    process_nextcloud_log(lines)

            total_buf = len(ipt_buffer) + len(f2b_buffer) + len(nginx_buffer) + len(ssh_buffer) + len(nc_auth_buffer)
            if total_buf > 0:
                flushed = flush_to_db(conn)
                if flushed > 0 and cycle % 10 == 0:
                    logging.info(f"Flushed {flushed} records (ipt={len(ipt_buffer)} f2b={len(f2b_buffer)} "
                                 f"nginx={len(nginx_buffer)} ssh={len(ssh_buffer)} nc={len(nc_auth_buffer)})")

            now = time.time()
            if now - last_metrics_time >= METRICS_INTERVAL:
                prev_net = record_metrics(conn, prev_net)
                last_metrics_time = now

            if now - last_cleanup_time >= 86400:
                cleanup_old_data(conn)
                last_cleanup_time = now

            try:
                conn.ping(True)
            except Exception:
                logging.warning("MySQL reconnecting...")
                try:
                    conn.close()
                except Exception:
                    pass
                conn = get_db()

            cycle += 1
            time.sleep(COLLECT_INTERVAL)

        except Exception as e:
            logging.error(f"Main loop error: {e}")
            time.sleep(10)

    try:
        flush_to_db(conn)
        conn.close()
    except Exception:
        pass

    try:
        os.remove(PID_FILE)
    except Exception:
        pass

    logging.info("Stats collector v2 stopped")

if __name__ == '__main__':
    main()