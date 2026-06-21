#!/usr/bin/env python3
"""
suricata_collector.py — Парсер Suricata eve.json в MySQL
Читает eve.json через seek (как modsec_collector), фильтрует только входящие
алерты (dst = наш IP), пишет bulk INSERT в таблицу suricata_alerts.
Плюс дублирует записи в ipt_drops для графиков PHP.

Запуск: python3 /usr/libexec/suritop-web/suricata_collector.py --daemon
"""

import json
import os
import sys
import time
import signal
import logging
from datetime import datetime
from collections import deque
from utils import LogTailer
from suritop_config import get_config

_cfg = get_config()

EVE_LOG = '/var/log/suricata/eve.json'
STATE_FILE = '/var/lib/stats_collector/suricata.pos'
DAEMON_LOG = '/var/log/suricata_collector.log'

COLLECT_INTERVAL = 15   # секунд между flush в БД
BATCH_SIZE = 300
OUR_IP = _cfg['our_ip']

# Шумные сигнатуры — пропускаем (не атаки, артефакты NAT/протоколов)
SKIP_SIG_PREFIXES = [
    'SURICATA STREAM',
    'SURICATA Applayer',
    'SURICATA QUIC',
    'SURICATA TLS',
    'SURICATA HTTP',
    'SURICATA SMB',
    'INFO Session Traversal Utilities',
]

# Категории для группировки
SEVERITY_MAP = {
    1: 'critical',
    2: 'warning',
    3: 'info',
}

# ── Логирование ──
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SURI] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def get_db():
    try:
        import MySQLdb
        conn = MySQLdb.connect(
            host=_cfg['db_host'], user=_cfg['db_user_w'], passwd=_cfg['db_pass_w'],
            db=_cfg['db_name'], charset='utf8mb4', connect_timeout=5
        )
        conn.autocommit(False)
        return conn
    except ImportError:
        import pymysql
        conn = pymysql.connect(
            host=_cfg['db_host'], user=_cfg['db_user_w'], password=_cfg['db_pass_w'],
            database=_cfg['db_name'], charset='utf8mb4',
            connect_timeout=5, autocommit=False
        )
        return conn

def is_private_ip(ip):
    if not ip:
        return True
    return (ip.startswith('10.') or ip.startswith('192.168.') or
            ip.startswith('172.16.') or ip.startswith('172.17.') or
            ip.startswith('172.18.') or ip.startswith('172.19.') or
            ip.startswith('172.2') or ip.startswith('172.3') or
            ip.startswith('127.') or ip.startswith('0.') or
            ip.startswith('169.254.'))


def parse_eve_lines(lines):
    alerts = []
    for line in lines:
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        if ev.get('event_type') != 'alert':
            continue

        alert = ev.get('alert', {})
        src_ip = ev.get('src_ip', '')
        dst_ip = ev.get('dest_ip', '')
        src_port = ev.get('src_port', 0)
        dst_port = ev.get('dest_port', 0)
        proto = ev.get('proto', '')
        timestamp = ev.get('timestamp', '')

        if is_private_ip(src_ip):
            continue
        if dst_ip != OUR_IP:
            continue

        sig_id = alert.get('signature_id', 0)
        sig_msg = alert.get('signature', '')[:512]
        category = alert.get('category', '')[:255]
        severity = alert.get('severity', 3)
        action = alert.get('action', 'allowed')

        if any(sig_msg.startswith(pfx) for pfx in SKIP_SIG_PREFIXES):
            continue

        try:
            ts = timestamp[:19].replace('T', ' ')
        except Exception:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        alerts.append({
            'src_ip': src_ip,
            'dst_port': dst_port,
            'proto': proto,
            'sig_id': sig_id,
            'sig_msg': sig_msg,
            'category': category,
            'severity': severity,
            'action': action,
            'logged_at': ts,
        })

    return alerts


def flush_to_db(conn, buffer):
    if not buffer:
        return 0
    cur = conn.cursor()

    # 1. Запись в таблицу сурикаты (для детальной статистики)
    sql_suri = """INSERT INTO suricata_alerts
             (src_ip, dst_port, proto, sig_id, sig_msg, category, severity, action, logged_at)
             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
    rows_suri = [(a['src_ip'], a['dst_port'], a['proto'], a['sig_id'],
             a['sig_msg'], a['category'], a['severity'], a['action'],
             a['logged_at']) for a in buffer]

    # 2. Дублирование в таблицу ipt_drops (для графиков активности на сайте)
    sql_ipt = """INSERT INTO ipt_drops (src_ip, dst_port, proto, logged_at)
                 VALUES (%s, %s, %s, %s)"""
    rows_ipt = [(a['src_ip'], a['dst_port'], a['proto'], a['logged_at']) for a in buffer]

    try:
        cur.executemany(sql_suri, rows_suri)
        cur.executemany(sql_ipt, rows_ipt) # Выполняем дублирование
        conn.commit()
        count = len(rows_suri)
        if count > 0:
            logging.info(f"Flushed {count} suricata alerts (and duplicated to ipt_drops)")
        return count
    except Exception as e:
        logging.error(f"DB write error: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return 0


def main():
    daemon_mode = '--daemon' in sys.argv

    if daemon_mode:
        logging.getLogger().handlers = []
        handler = logging.FileHandler(DAEMON_LOG)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [SURI] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

    logging.info("=== suricata_collector starting ===")
    logging.info(f"Eve log: {EVE_LOG}")
    logging.info(f"Our IP: {OUR_IP}")
    logging.info(f"Flush interval: {COLLECT_INTERVAL}s, batch: {BATCH_SIZE}")

    conn = get_db()
    logging.info("DB connected")

    tailer = LogTailer(EVE_LOG, STATE_FILE)
    buffer = deque(maxlen=BATCH_SIZE * 3)

    running = True
    def handle_signal(signum, frame):
        nonlocal running
        logging.info(f"Signal {signum}, shutting down...")
        running = False
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    last_flush = time.time()

    while running:
        try:
            lines = tailer.read_new_lines()
            if lines:
                alerts = parse_eve_lines(lines)
                buffer.extend(alerts)

            now = time.time()
            if now - last_flush >= COLLECT_INTERVAL or len(buffer) >= BATCH_SIZE:
                if buffer:
                    batch = list(buffer)
                    buffer.clear()
                    try:
                        flush_to_db(conn, batch)
                    except Exception as e:
                        logging.error(f"Flush error: {e}")
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn = get_db()
                last_flush = now

            time.sleep(2)

        except KeyboardInterrupt:
            break
        except Exception as e:
            logging.error(f"Main loop error: {e}")
            time.sleep(5)
            try:
                conn.close()
            except Exception:
                pass
            conn = get_db()

    if buffer:
        flush_to_db(conn, list(buffer))
    conn.close()
    logging.info("=== suricata_collector stopped ===")


if __name__ == '__main__':
    main()