#!/usr/bin/env python3
"""
suritop-patch.py — Patches installed Python scripts to read from config
Run during src_install() or manually after installation.
"""

import os
import re
import sys

PATCHES = {
    'stats_collector.py': {
        'imports': 'from suritop_config import get_db as _sdb, get_config as _scfg\n',
        'replacements': [
            (r"^DB_HOST = '.*'", "DB_HOST = _scfg()['db_host']"),
            (r"^DB_NAME = '.*'", "DB_NAME = _scfg()['db_name']"),
            (r"^DB_USER = '.*'", "DB_USER = _scfg()['db_user_w']"),
            (r"^DB_PASS = '.*'", "DB_PASS = _scfg()['db_pass_w']"),
        ],
    },
    'suricata_collector.py': {
        'imports': 'from suritop_config import get_db as _sdb, get_config as _scfg\n',
        'replacements': [
            (r"^DB_HOST = '.*'", "DB_HOST = _scfg()['db_host']"),
            (r"^DB_NAME = '.*'", "DB_NAME = _scfg()['db_name']"),
            (r"^DB_USER = '.*'", "DB_USER = _scfg()['db_user_w']"),
            (r"^DB_PASS = '.*'", "DB_PASS = _scfg()['db_pass_w']"),
        ],
    },
    'modsec_collector.py': {
        'imports': 'from suritop_config import get_db as _sdb, get_config as _scfg\n',
        'replacements': [
            (r"^DB_HOST = '.*'", "DB_HOST = _scfg()['db_host']"),
            (r"^DB_NAME = '.*'", "DB_NAME = _scfg()['db_name']"),
            (r"^DB_USER = '.*'", "DB_USER = _scfg()['db_user_w']"),
            (r"^DB_PASS = '.*'", "DB_PASS = _scfg()['db_pass_w']"),
        ],
    },
    'geo_fill.py': {
        'imports': 'from suritop_config import get_db as _sdb, get_config as _scfg\n',
        'replacements': [
            (r"^DB_HOST = '.*'", "DB_HOST = _scfg()['db_host']"),
            (r"^DB_NAME = '.*'", "DB_NAME = _scfg()['db_name']"),
            (r"^DB_USER = '.*'", "DB_USER = _scfg()['db_user_w']"),
            (r"^DB_PASS = '.*'", "DB_PASS = _scfg()['db_pass_w']"),
        ],
    },
    'suritop.py': {
        'imports': 'from suritop_config import get_db as _sdb, get_config as _scfg\n',
        'replacements': [
            (r"^DB_HOST='.*'", "DB_HOST=_scfg()['db_host']"),
            (r"^DB_NAME='.*'", "DB_NAME=_scfg()['db_name']"),
            (r"^DB_USER='.*'", "DB_USER=_scfg()['db_user_w']"),
            (r"^DB_PASS='.*'", "DB_PASS=_scfg()['db_pass_w']"),
        ],
    },
}

COLLECTOR_CONF_REPLACEMENTS = [
    ("config.read('/usr/libexec/suritop-web/collector.conf')",
     "config.read('/etc/suritop-web/collector.conf')"),
    ("config.read(\"/usr/libexec/suritop-web/collector.conf\")",
     "config.read(\"/etc/suritop-web/collector.conf\")"),
]


def patch_file(filepath, spec):
    """Apply patches to a single file."""
    if not os.path.exists(filepath):
        print(f"  SKIP: {filepath} not found")
        return False

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    original = content

    # Add imports after first import block
    if spec['imports'] not in content:
        # Find first "import" line and add after it
        lines = content.split('\n')
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.startswith('import ') or line.startswith('from '):
                insert_idx = i + 1
                break
        lines.insert(insert_idx, spec['imports'].rstrip())
        content = '\n'.join(lines)

    # Apply replacements
    for pattern, replacement in spec['replacements']:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)

    # Fix collector.conf path
    for old, new in COLLECTOR_CONF_REPLACEMENTS:
        content = content.replace(old, new)

    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  PATCHED: {os.path.basename(filepath)}")
        return True
    else:
        print(f"  NO CHANGE: {os.path.basename(filepath)}")
        return False


def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else '/usr/libexec/suritop-web'

    print(f"Patching Python scripts in {target_dir}...")
    patched = 0

    for filename, spec in PATCHES.items():
        filepath = os.path.join(target_dir, filename)
        if patch_file(filepath, spec):
            patched += 1

    print(f"\nDone: {patched}/{len(PATCHES)} files patched")


if __name__ == '__main__':
    main()
