#!/usr/bin/env python3
"""
modsec_collector.py — Парсер ModSecurity audit log в MySQL
Плюс дублирует записи в ipt_drops для графиков PHP.
Запуск: python3 /usr/libexec/suritop-web/modsec_collector.py --daemon

Таблица: waf_blocks (создаётся автоматически)
"""

import re
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

MODSEC_LOG = '/var/log/modsec_audit.log'
STATE_FILE = '/var/lib/stats_collector/modsec.pos'
DAEMON_LOG = '/var/log/modsec_collector.log'

COLLECT_INTERVAL = 30  # секунд между flush в БД
BATCH_SIZE = 200

# ── Regex для парсинга audit log ──
RE_SECTION_A = re.compile(r'---(\w+)---A--')
RE_A_DATA = re.compile(r'\[([^\]]+)\]\s+[\d.]+ ([\d.]+) \d+ ([\d.]+) \d+')
RE_REQUEST_LINE = re.compile(r'^(\w+)\s+(\S+)\s+HTTP/')
RE_HOST = re.compile(r'^Host:\s*(\S+)', re.IGNORECASE)
RE_MODSEC_MSG = re.compile(r'ModSecurity:\s+(?:Warning\.|Access denied.*?)\s+.*?\[id "(\d+)"\].*?\[msg "([^"]+)"\]')
RE_MODSEC_DENIED = re.compile(r'ModSecurity:\s+Access denied with code (\d+)')
RE_MODSEC_URI = re.compile(r'\[uri "([^"]+)"\]')
RE_MODSEC_SEVERITY = re.compile(r'\[severity "(\d+)"\]')

# ── Глобальные ──
buffer = deque()
running = True

logging.basicConfig(
    filename=DAEMON_LOG,
    level=logging.INFO,
    format='%(asctime)s [MODSEC] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def get_db():
    try:
        import MySQLdb
        conn = MySQLdb.connect(
            host=_cfg['db_host'], user=_cfg['db_user_w'], passwd=_cfg['db_pass_w'],
            db=_cfg['db_name'], charset='utf8mb4', connect_timeout=5
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


def create_table(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS waf_blocks (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            src_ip VARCHAR(45) NOT NULL,
            host VARCHAR(255) DEFAULT '',
            uri VARCHAR(2048) DEFAULT '',
            method VARCHAR(10) DEFAULT '',
            rule_id INT UNSIGNED DEFAULT 0,
            rule_msg VARCHAR(512) DEFAULT '',
            status_code SMALLINT UNSIGNED DEFAULT 403,
            severity TINYINT UNSIGNED DEFAULT 0,
            logged_at DATETIME NOT NULL,
            INDEX idx_logged (logged_at),
            INDEX idx_ip (src_ip),
            INDEX idx_rule (rule_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    conn.commit()
    logging.info("Table waf_blocks OK")


def parse_audit_entries(lines):
    entries = {}
    current_id = None
    current_section = None

    for line in lines:
        line = line.rstrip('\n\r')
        if line.startswith('---') and line.endswith('--'):
            parts = line.strip('-').strip()
            if len(parts) >= 2:
                entry_id = parts[:-1]
                section = parts[-1]
                if section == 'A':
                    current_id = entry_id
                    if current_id not in entries:
                        entries[current_id] = {}
                elif current_id and entry_id == current_id:
                    pass
                current_section = section
                if current_id and current_section not in entries.get(current_id, {}):
                    entries.setdefault(current_id, {})[current_section] = []
            continue

        if current_id and current_section and current_id in entries:
            entries[current_id].setdefault(current_section, []).append(line)

    results = []
    for eid, sections in entries.items():
        h_lines = sections.get('H', [])
        if not h_lines:
            continue

        h_text = '\n'.join(h_lines)
        denied_match = RE_MODSEC_DENIED.search(h_text)
        if not denied_match:
            continue

        status_code = int(denied_match.group(1))

        a_lines = sections.get('A', [])
        src_ip = ''
        logged_at = datetime.now()
        for al in a_lines:
            am = RE_A_DATA.search(al)
            if am:
                try:
                    logged_at = datetime.strptime(am.group(1), '%d/%b/%Y:%H:%M:%S %z')
                    logged_at = logged_at.replace(tzinfo=None)
                except Exception:
                    try:
                        logged_at = datetime.strptime(
                            am.group(1).split(' ')[0], '%d/%b/%Y:%H:%M:%S'
                        )
                    except Exception:
                        logged_at = datetime.now()
                src_ip = am.group(2)

        if not src_ip:
            continue

        b_lines = sections.get('B', [])
        method = ''
        uri = ''
        host = ''
        for bl in b_lines:
            if not method:
                rm = RE_REQUEST_LINE.match(bl)
                if rm:
                    method = rm.group(1)
                    uri = rm.group(2)[:2048]
            hm = RE_HOST.match(bl)
            if hm:
                host = hm.group(1)[:255]

        rule_id = 0
        rule_msg = ''
        severity = 0

        for hl in h_lines:
            mm = RE_MODSEC_MSG.search(hl)
            if mm:
                rid = int(mm.group(1))
                if rid != 949110 and rid != 980130:
                    if rule_id == 0:
                        rule_id = rid
                        rule_msg = mm.group(2)[:512]
            sm = RE_MODSEC_SEVERITY.search(hl)
            if sm and severity == 0:
                severity = int(sm.group(1))

        if rule_id == 0:
            rule_id = 949110
            rule_msg = 'Inbound Anomaly Score Exceeded'

        results.append((
            src_ip, host, uri, method, rule_id,
            rule_msg, status_code, severity,
            logged_at.strftime('%Y-%m-%d %H:%M:%S')
        ))

    return results


def flush_to_db(conn):
    if not buffer:
        return 0
    cur = conn.cursor()
    batch = []
    while buffer and len(batch) < BATCH_SIZE:
        batch.append(buffer.popleft())
    if batch:
        try:
            # 1. Запись в WAF блокировки
            cur.executemany(
                """INSERT INTO waf_blocks
                   (src_ip, host, uri, method, rule_id, rule_msg, status_code, severity, logged_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                batch
            )

            # 2. Дублирование в ipt_drops (для графиков активности)
            # В batch: [0] - src_ip, [8] - logged_at
            # Эмулируем dst_port 443 и TCP
            ipt_batch = [(b[0], 443, 'TCP', b[8]) for b in batch]
            cur.executemany(
                """INSERT INTO ipt_drops (src_ip, dst_port, proto, logged_at)
                   VALUES (%s, %s, %s, %s)""",
                ipt_batch
            )

            conn.commit()
            return len(batch)
        except Exception as e:
            logging.error(f"DB error: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
    return 0


def signal_handler(sig, frame):
    global running
    logging.info(f"Signal {sig}, stopping...")
    running = False


def main():
    global running

    daemon_mode = '--daemon' in sys.argv

    logging.info("ModSecurity collector starting...")
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    conn = get_db()
    logging.info("Connected to MySQL")

    tailer = LogTailer(MODSEC_LOG, STATE_FILE)
    logging.info(f"Monitoring: {MODSEC_LOG}")

    if not daemon_mode:
        lines = tailer.read_new_lines()
        if lines:
            entries = parse_audit_entries(lines)
            for e in entries:
                buffer.append(e)
            flushed = flush_to_db(conn)
            logging.info(f"Done! Parsed {len(entries)}, flushed {flushed}")
        else:
            logging.info("No new lines")
        conn.close()
        return

    logging.info("Running as daemon")
    while running:
        try:
            try:
                conn.ping(False)
            except Exception:
                conn = get_db()

            lines = tailer.read_new_lines()
            if lines:
                entries = parse_audit_entries(lines)
                for e in entries:
                    buffer.append(e)

            if buffer:
                flushed = flush_to_db(conn)
                if flushed:
                    logging.info(f"Flushed {flushed} WAF blocks (and duplicated to ipt_drops)")

        except Exception as e:
            logging.error(f"Loop error: {e}")

        time.sleep(COLLECT_INTERVAL)

    try:
        flush_to_db(conn)
        conn.close()
    except Exception:
        pass
    logging.info("Stopped")


if __name__ == '__main__':
    main()