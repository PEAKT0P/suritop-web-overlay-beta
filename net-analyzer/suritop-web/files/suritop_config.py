#!/usr/bin/env python3
"""
suritop_config.py — Shared configuration reader for suritop-web
Reads from /etc/suritop-web/collector.conf and /etc/conf.d/suritop-web

Usage in other scripts:
    from suritop_config import get_db, get_config
    cfg = get_config()
    conn = get_db()
"""

import os
import configparser

CONFIG_PATH = '/etc/suritop-web/collector.conf'
CONFD_PATH = '/etc/conf.d/suritop-web'

_config = None
_env_loaded = False


def _load_env():
    """Load /etc/conf.d/suritop-web into os.environ"""
    global _env_loaded
    if _env_loaded:
        return
    _env_loaded = True
    if os.path.exists(CONFD_PATH):
        with open(CONFD_PATH, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, val = line.partition('=')
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                    if val.startswith("'") and val.endswith("'"):
                        val = val[1:-1]
                    os.environ.setdefault(key, val)


def get_config():
    """Get all config values as a dict"""
    global _config
    if _config is not None:
        return _config

    _load_env()

    conf = configparser.ConfigParser()
    conf.read(CONFIG_PATH)

    _config = {
        'db_host': os.environ.get('SURITOP_DB_HOST',
                    conf.get('Database', 'host', fallback='localhost')),
        'db_name': os.environ.get('SURITOP_DB_NAME',
                    conf.get('Database', 'name', fallback='server_stats')),
        'db_user_r': os.environ.get('SURITOP_DB_USER_R',
                     conf.get('Database', 'user_r', fallback='stats_reader')),
        'db_pass_r': os.environ.get('SURITOP_DB_PASS_R',
                     conf.get('Database', 'pass_r', fallback='')),
        'db_user_w': os.environ.get('SURITOP_DB_USER_W',
                     conf.get('Database', 'user_w', fallback='stats_writer')),
        'db_pass_w': os.environ.get('SURITOP_DB_PASS_W',
                     conf.get('Database', 'pass_w', fallback='')),
        'our_ip': os.environ.get('SURITOP_SERVER_IP',
                  conf.get('Network', 'our_ip', fallback='127.0.0.1')),
        'net_interface': os.environ.get('SURITOP_NET_INTERFACE',
                         conf.get('Interfaces', 'monitor', fallback='eth0')),
    }
    return _config


def get_db(readonly=False):
    """Get a database connection. Set readonly=True for reader account."""
    cfg = get_config()

    if readonly:
        user = cfg['db_user_r']
        passwd = cfg['db_pass_r']
    else:
        user = cfg['db_user_w']
        passwd = cfg['db_pass_w']

    try:
        import MySQLdb
        conn = MySQLdb.connect(
            host=cfg['db_host'], user=user, passwd=passwd,
            db=cfg['db_name'], charset='utf8mb4',
            connect_timeout=5
        )
        conn.autocommit(True)
        return conn
    except ImportError:
        import pymysql
        conn = pymysql.connect(
            host=cfg['db_host'], user=user, password=passwd,
            database=cfg['db_name'], charset='utf8mb4',
            connect_timeout=5, autocommit=True
        )
        return conn
