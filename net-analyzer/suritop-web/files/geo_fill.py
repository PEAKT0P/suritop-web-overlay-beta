#!/usr/bin/env python3
"""
geo_fill.py v2.1 — Заполняет таблицу geo_cache (Gentoo Edition + Panic Mode)
Источники: ipt_drops, f2b_actions, nginx_blocks, ssh_attacks, nc_auth_fails

Использует:
  1) ip-api.com для штатной работы (lat, lon, country)
  2) Системный geoiplookup как Fallback при DDoS (только country)

Никаких pip-модулей. Никаких долгих зависаний при 429 ошибке.
"""

sys.path.insert(0, '/usr/libexec/suritop-web')
from suritop_config import get_db, get_config
import sys
import time
import json
import subprocess
import logging
from urllib.request import urlopen, Request
from urllib.error import URLError

# ── Конфигурация БД ──
_cfg = get_config()
DB_HOST = _cfg["db_host"]
DB_NAME = _cfg["db_name"]
DB_USER = _cfg["db_user_w"]
DB_PASS = _cfg["db_pass_w"]

BATCH_API_URL = 'http://ip-api.com/batch'
BATCH_SIZE = 100

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [GEO] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def get_db():
    try:
        import MySQLdb
        conn = MySQLdb.connect(
            host=DB_HOST, user=DB_USER, passwd=DB_PASS,
            db=DB_NAME, charset='utf8mb4', connect_timeout=5
        )
        conn.autocommit(True)
        return conn
    except ImportError:
        import pymysql
        conn = pymysql.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASS,
            database=DB_NAME, charset='utf8mb4',
            connect_timeout=5, autocommit=True
        )
        return conn


def get_country_local(ip):
    """Получить страну через системный geoiplookup (мгновенно)"""
    try:
        out = subprocess.check_output(
            ['geoiplookup', ip], timeout=3, text=True, stderr=subprocess.DEVNULL
        )
        for line in out.strip().split('\n'):
            if 'Country Edition' in line and 'not found' not in line.lower():
                parts = line.split(': ', 1)
                if len(parts) == 2:
                    return parts[1]
        return "Unknown"
    except Exception:
        return "Unknown"


def batch_geolocate(ips):
    """Пакетный запрос к ip-api.com. Возвращает '429', если лимит исчерпан."""
    payload = json.dumps([
        {"query": ip, "fields": "status,country,lat,lon,query"}
        for ip in ips
    ]).encode('utf-8')

    req = Request(
        BATCH_API_URL,
        data=payload,
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data
    except URLError as e:
        if hasattr(e, 'code') and e.code == 429:
            return "429"
        logging.error(f"API error: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return None


def fill_missing(conn):
    """Находит IP без geo_cache и заполняет"""
    cur = conn.cursor()

    cur.execute("""
        SELECT DISTINCT ip COLLATE utf8mb4_unicode_ci AS ip FROM (
            SELECT src_ip COLLATE utf8mb4_unicode_ci AS ip FROM ipt_drops
            UNION
            SELECT src_ip COLLATE utf8mb4_unicode_ci AS ip FROM f2b_actions
            UNION
            SELECT src_ip COLLATE utf8mb4_unicode_ci AS ip FROM nginx_blocks
            UNION
            SELECT src_ip COLLATE utf8mb4_unicode_ci AS ip FROM ssh_attacks
            UNION
            SELECT src_ip COLLATE utf8mb4_unicode_ci AS ip FROM nc_auth_fails
            UNION
            SELECT src_ip COLLATE utf8mb4_unicode_ci AS ip FROM suricata_alerts
        ) all_ips
        WHERE ip NOT IN (SELECT ip COLLATE utf8mb4_unicode_ci FROM geo_cache)
        AND ip NOT LIKE '10.%'
        AND ip NOT LIKE '192.168.%'
        AND ip NOT LIKE '172.1_.%'
        AND ip NOT LIKE '172.2_.%'
        AND ip NOT LIKE '172.3_.%'
        AND ip NOT LIKE '127.%'
        AND ip != ''
        LIMIT 2000
    """)

    missing = [row[0] for row in cur.fetchall()]

    if not missing:
        return 0

    logging.info(f"Найдено {len(missing)} IP без геоданных")
    filled = 0
    api_ok = True  # Флаг состояния API

    for i in range(0, len(missing), BATCH_SIZE):
        batch = missing[i:i + BATCH_SIZE]
        insert_data = []

        if api_ok:
            results = batch_geolocate(batch)
            if results == "429":
                logging.warning("Сработал лимит API (429)! Включаем Fallback на локальный geoiplookup.")
                api_ok = False
            elif results is None:
                logging.error("Сбой API. Включаем Fallback на локальный geoiplookup.")
                api_ok = False

        if not api_ok:
            # РЕЖИМ ПАНИКИ: Мгновенно перевариваем очередь локально
            for ip in batch:
                country = get_country_local(ip)
                # Передаем None для координат (будет NULL в базе)
                insert_data.append((ip, None, None, country))
        else:
            # ШТАТНЫЙ РЕЖИМ: Разбираем ответ API
            for r in results:
                if r.get('status') == 'success':
                    ip = r['query']
                    lat = r.get('lat')
                    lon = r.get('lon')
                    country = r.get('country')

                    if not country:
                        country = get_country_local(ip)

                    insert_data.append((ip, lat, lon, country))

        # Пишем в БД
        if insert_data:
            try:
                cur.executemany(
                    """INSERT INTO geo_cache (ip, lat, lon, country)
                       VALUES (%s, %s, %s, %s)
                       ON DUPLICATE KEY UPDATE lat=VALUES(lat), lon=VALUES(lon),
                       country=VALUES(country), updated_at=NOW()""",
                    insert_data
                )
                conn.commit()
                filled += len(insert_data)
            except Exception as e:
                logging.error(f"DB insert error: {e}")

        # Небольшая пауза только если API работает, чтобы не спамить
        if api_ok and i + BATCH_SIZE < len(missing):
            time.sleep(1.5)

    logging.info(f"Итого заполнено: {filled} IP")
    return filled


def main():
    daemon_mode = '--daemon' in sys.argv

    conn = get_db()
    logging.info("Подключение к MySQL OK")

    if daemon_mode:
        logging.info("Запущен в режиме демона (каждые 5 мин)")
        while True:
            try:
                try:
                    conn.ping(False) # Отключен автореконнект для Python 3.13
                except Exception:
                    conn = get_db()
                fill_missing(conn)
            except Exception as e:
                logging.error(f"Ошибка: {e}")
            time.sleep(300)
    else:
        filled = fill_missing(conn)
        logging.info(f"Готово! Заполнено {filled} записей")
        conn.close()


if __name__ == '__main__':
    main()