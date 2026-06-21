#!/usr/bin/env python3
"""
iptables-manager API daemon
Собирает данные об iptables, открытых портах, Docker, fail2ban, Suricata
и предоставляет JSON API через Unix-сокет.

Работает под root (нужен доступ к iptables).
Управляется через OpenRC init-скрипт.
"""

import json
import subprocess
import os
import sys
import re
import time
import signal
import socket
import threading
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import UnixStreamServer, StreamRequestHandler
from datetime import datetime
sys.path.insert(0, '/usr/libexec/suritop-web')
from suritop_config import get_config
_cfg = get_config()
NET_IF = _cfg.get('net_interface', 'eth0')

# ─── Конфигурация ───
SOCKET_PATH = "/tmp/iptables-manager.sock"
CACHE_TTL = 10  # секунд между обновлениями кэша
PID_FILE = "/tmp/iptables-manager.pid"
LOG_FILE = "/var/log/iptables-manager.log"

# Белый список команд для управления правилами
ALLOWED_ACTIONS = {
    "block_ip", "unblock_ip",
    "open_port", "close_port",
    "list_rules", "list_ports",
    "list_docker", "list_fail2ban",
    "system_info", "full_report",
    "list_nat", "list_forward",
    "list_connections",
}

# Порты которые НИКОГДА нельзя открыть наружу
DANGEROUS_PORTS = {22, 53, 123, 139, 161, 445, 3306, 3389, 5900, 6379, 11211, 33060}

# ─── Кэш данных ───
_cache = {}
_cache_time = 0
_cache_lock = threading.Lock()


def log(msg):
    """Логирование в файл"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except:
        pass


def run_cmd(cmd, timeout=10):
    """Безопасный запуск команды"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"ERROR: timeout ({timeout}s)"
    except Exception as e:
        return f"ERROR: {e}"


def get_iptables_rules():
    """Получить все правила iptables по таблицам"""
    tables = {}

    # filter table
    raw = run_cmd("iptables -L -n -v --line-numbers 2>/dev/null")
    tables["filter"] = parse_iptables_output(raw)

    # nat table
    raw = run_cmd("iptables -t nat -L -n -v --line-numbers 2>/dev/null")
    tables["nat"] = parse_iptables_output(raw)

    # mangle table
    raw = run_cmd("iptables -t mangle -L -n -v --line-numbers 2>/dev/null")
    tables["mangle"] = parse_iptables_output(raw)

    return tables


def parse_iptables_output(raw):
    """Парсинг вывода iptables -L -n -v --line-numbers"""
    chains = {}
    current_chain = None
    current_policy = None

    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Chain INPUT (policy DROP)
        chain_match = re.match(r"Chain\s+(\S+)\s+\(policy\s+(\S+)\s", line)
        if chain_match:
            current_chain = chain_match.group(1)
            current_policy = chain_match.group(2)
            chains[current_chain] = {"policy": current_policy, "rules": []}
            continue

        # Chain без policy (user-defined)
        chain_match2 = re.match(r"Chain\s+(\S+)\s+\(", line)
        if chain_match2 and not chain_match:
            current_chain = chain_match2.group(1)
            chains[current_chain] = {"policy": "-", "rules": []}
            continue

        # Пропускаем заголовки
        if line.startswith("num") or line.startswith("pkts"):
            continue

        # Парсим правило
        if current_chain and re.match(r"^\d+", line):
            parts = line.split(None, 10)
            if len(parts) >= 9:
                rule = {
                    "num": parts[0],
                    "pkts": parts[1],
                    "bytes": parts[2],
                    "target": parts[3],
                    "prot": parts[4],
                    "opt": parts[5],
                    "in": parts[6],
                    "out": parts[7],
                    "source": parts[8],
                    "destination": parts[9] if len(parts) > 9 else "0.0.0.0/0",
                    "extra": parts[10] if len(parts) > 10 else "",
                }
                chains[current_chain]["rules"].append(rule)

    return chains


def get_listening_ports():
    """Получить все слушающие порты"""
    ports = []
    raw = run_cmd("ss -tlnp 2>/dev/null")

    for line in raw.split("\n")[1:]:  # skip header
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 6:
            listen_addr = parts[3]
            process = parts[5] if len(parts) > 5 else ""

            # Парсим адрес:порт
            if ":" in listen_addr:
                addr, port = listen_addr.rsplit(":", 1)
                try:
                    port = int(port)
                except:
                    continue

                # Определяем тип привязки
                if addr in ("0.0.0.0", "*", "[::]", "::"):
                    bind_type = "all"
                elif addr in ("127.0.0.1", "::1"):
                    bind_type = "localhost"
                else:
                    bind_type = "specific"

                # Извлекаем имя процесса
                proc_name = ""
                proc_match = re.search(r'"([^"]+)"', process)
                if proc_match:
                    proc_name = proc_match.group(1)

                ports.append({
                    "port": port,
                    "addr": addr,
                    "bind": bind_type,
                    "process": proc_name,
                    "raw": listen_addr,
                })

    # Также UDP
    raw_udp = run_cmd("ss -ulnp 2>/dev/null")
    for line in raw_udp.split("\n")[1:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 6:
            listen_addr = parts[3]
            process = parts[5] if len(parts) > 5 else ""
            if ":" in listen_addr:
                addr, port = listen_addr.rsplit(":", 1)
                try:
                    port = int(port)
                except:
                    continue
                if addr in ("0.0.0.0", "*", "[::]", "::"):
                    bind_type = "all"
                elif addr in ("127.0.0.1", "::1"):
                    bind_type = "localhost"
                else:
                    bind_type = "specific"
                proc_name = ""
                proc_match = re.search(r'"([^"]+)"', process)
                if proc_match:
                    proc_name = proc_match.group(1)
                ports.append({
                    "port": port,
                    "addr": addr,
                    "bind": bind_type,
                    "process": proc_name,
                    "proto": "udp",
                    "raw": listen_addr,
                })

    # Отмечаем TCP порты без proto
    for p in ports:
        if "proto" not in p:
            p["proto"] = "tcp"

    return ports


def check_port_firewall_status(ports, iptables_rules):
    """Проверяем, какие порты открыты/закрыты файрволом на внешнем интерфейсе"""
    input_rules = iptables_rules.get("filter", {}).get("INPUT", {}).get("rules", [])

    result = []
    for p in ports:
        port_num = p["port"]
        proto = p.get("proto", "tcp")

        status = analyze_port_access(port_num, proto, input_rules)
        p["fw_status"] = status
        result.append(p)

    return result


def analyze_port_access(port, proto, input_rules):
    """
    Анализируем, пропускает ли файрвол трафик на порт через интерфейс.
    Возвращает: 'open', 'blocked', 'limited', 'unknown'
    """
    for rule in input_rules:
        iface = rule.get("in", "*")
        target = rule.get("target", "")
        extra = rule.get("extra", "")
        rule_proto = rule.get("prot", "all")

        # Ищем правила с нашим портом
        dport_match = re.search(r"dpt[s]?:(\d+)(?::(\d+))?", extra)
        if dport_match:
            port_start = int(dport_match.group(1))
            port_end = int(dport_match.group(2)) if dport_match.group(2) else port_start

            if port_start <= port <= port_end:
                if rule_proto != "all" and rule_proto != proto:
                    continue

                if iface == NET_IF or iface == "*":
                    if target == "DROP" or target == "REJECT":
                        return "blocked"
                    elif target == "ACCEPT":
                        if "limit" in extra:
                            return "limited"
                        return "open"

    # Проверяем общие правила ACCEPT/DROP для интерфейса
    for rule in input_rules:
        iface = rule.get("in", "*")
        target = rule.get("target", "")
        extra = rule.get("extra", "")

        # conntrack ESTABLISHED,RELATED
        if "ESTABLISHED" in extra and target == "ACCEPT":
            continue  # не считаем это открытием порта

        # Если есть blanket ACCEPT для интерфейса без порта
        if iface == NET_IF and target == "ACCEPT" and "dpt" not in extra:
            return "open"

    return "blocked_by_policy"  # policy DROP


def get_docker_info():
    """Информация о Docker контейнерах и их портах"""
    containers = []
    raw = run_cmd("docker ps --format '{{.Names}}|{{.Status}}|{{.Ports}}|{{.Image}}' 2>/dev/null")
    if raw and not raw.startswith("ERROR"):
        for line in raw.split("\n"):
            if "|" in line:
                parts = line.split("|", 3)
                containers.append({
                    "name": parts[0],
                    "status": parts[1],
                    "ports": parts[2],
                    "image": parts[3] if len(parts) > 3 else "",
                })

    # Docker networks
    networks = run_cmd("docker network ls --format '{{.Name}}|{{.Driver}}' 2>/dev/null")
    net_list = []
    if networks and not networks.startswith("ERROR"):
        for line in networks.split("\n"):
            if "|" in line:
                parts = line.split("|")
                net_list.append({"name": parts[0], "driver": parts[1]})

    return {"containers": containers, "networks": net_list}


def get_fail2ban_info():
    """Информация о fail2ban"""
    jails = []
    raw = run_cmd("fail2ban-client status 2>/dev/null")
    if raw and not raw.startswith("ERROR"):
        jail_match = re.search(r"Jail list:\s+(.+)", raw)
        if jail_match:
            jail_names = [j.strip() for j in jail_match.group(1).split(",")]
            for jail_name in jail_names:
                jail_info = run_cmd(f"fail2ban-client status {jail_name} 2>/dev/null")
                banned = 0
                total = 0
                banned_ips = []
                if jail_info:
                    b_match = re.search(r"Currently banned:\s+(\d+)", jail_info)
                    t_match = re.search(r"Total banned:\s+(\d+)", jail_info)
                    ip_match = re.search(r"Banned IP list:\s+(.*)", jail_info)
                    if b_match:
                        banned = int(b_match.group(1))
                    if t_match:
                        total = int(t_match.group(1))
                    if ip_match and ip_match.group(1).strip():
                        banned_ips = ip_match.group(1).strip().split()

                jails.append({
                    "name": jail_name,
                    "banned": banned,
                    "total_banned": total,
                    "banned_ips": banned_ips[:20],  # лимит
                })

    return jails


def get_suricata_info():
    """Базовая информация о Suricata"""
    info = {"running": False, "stats": {}}

    pid = run_cmd("pgrep -f /usr/bin/suricata 2>/dev/null")
    info["running"] = bool(pid.strip())

    # Последние алерты
    alerts = []
    raw = run_cmd("tail -20 /var/log/suricata/fast.log 2>/dev/null")
    if raw and not raw.startswith("ERROR"):
        for line in raw.split("\n"):
            if line.strip():
                alerts.append(line.strip()[:200])
    info["recent_alerts"] = alerts[-10:]

    return info


def get_connections_info():
    """Активные соединения — только внешние, сортированные"""
    conns = []
    raw = run_cmd("ss -tn state established 2>/dev/null")
    if raw:
        for line in raw.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 4:
                local = parts[2]
                remote = parts[3]

                # Пропускаем localhost <-> localhost
                local_addr = local.rsplit(":", 1)[0] if ":" in local else local
                remote_addr = remote.rsplit(":", 1)[0] if ":" in remote else remote

                if local_addr in ("127.0.0.1", "::1", "[::1]") and remote_addr in ("127.0.0.1", "::1", "[::1]"):
                    continue
                # Пропускаем docker internal
                if local_addr.startswith("172.17.") and remote_addr.startswith("172.17."):
                    continue

                is_external = not remote_addr.startswith(("127.", "192.168.", "10.", "172.16.", "172.17.", "::1", "[::1]"))

                conns.append({
                    "local": local,
                    "remote": remote,
                    "external": is_external,
                })

    # Сортировка: внешние первые, потом LAN
    conns.sort(key=lambda c: (0 if c["external"] else 1, c["remote"]))
    return conns[:50]


def get_system_info():
    """Общая системная информация"""
    uptime = run_cmd("uptime -p 2>/dev/null")
    hostname = run_cmd("hostname 2>/dev/null")
    kernel = run_cmd("uname -r 2>/dev/null")
    load = run_cmd("cat /proc/loadavg 2>/dev/null")
    mem = run_cmd("free -h 2>/dev/null | grep Mem")

    mem_info = {}
    if mem:
        parts = mem.split()
        if len(parts) >= 6:
            mem_info = {
                "total": parts[1],
                "used": parts[2],
                "free": parts[3],
                "available": parts[6] if len(parts) > 6 else parts[3],
            }

    return {
        "hostname": hostname,
        "kernel": kernel,
        "uptime": uptime,
        "load": load,
        "memory": mem_info,
        "timestamp": datetime.now().isoformat(),
    }


def get_interfaces():
    """Сетевые интерфейсы"""
    interfaces = []
    raw = run_cmd("ip -br addr 2>/dev/null")
    if raw:
        for line in raw.split("\n"):
            parts = line.split()
            if len(parts) >= 2:
                interfaces.append({
                    "name": parts[0],
                    "state": parts[1],
                    "addresses": parts[2:],
                })
    return interfaces


def collect_all_data():
    """Собрать все данные (с кэшированием)"""
    global _cache, _cache_time

    now = time.time()
    with _cache_lock:
        if now - _cache_time < CACHE_TTL and _cache:
            return _cache

    try:
        iptables_rules = get_iptables_rules()
        listening_ports = get_listening_ports()
        ports_with_fw = check_port_firewall_status(listening_ports, iptables_rules)

        data = {
            "system": get_system_info(),
            "interfaces": get_interfaces(),
            "iptables": iptables_rules,
            "ports": ports_with_fw,
            "docker": get_docker_info(),
            "fail2ban": get_fail2ban_info(),
            "suricata": get_suricata_info(),
            "connections": get_connections_info(),
            "collected_at": datetime.now().isoformat(),
        }

        with _cache_lock:
            _cache = data
            _cache_time = now

        return data
    except Exception as e:
        log(f"Error collecting data: {e}\n{traceback.format_exc()}")
        return {"error": str(e)}


# ─── Управление правилами ───

def action_block_ip(ip):
    """Заблокировать IP на интерфейс"""
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", ip):
        return {"error": "Invalid IP format"}

    result = run_cmd(f"iptables -I INPUT 1 -s {ip} -i {NET_IF} -j DROP")
    log(f"ACTION: block_ip {ip} -> {result}")
    return {"ok": True, "action": "block_ip", "ip": ip}


def action_unblock_ip(ip):
    """Разблокировать IP"""
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", ip):
        return {"error": "Invalid IP format"}

    result = run_cmd(f"iptables -D INPUT -s {ip} -i {NET_IF} -j DROP")
    log(f"ACTION: unblock_ip {ip} -> {result}")
    return {"ok": True, "action": "unblock_ip", "ip": ip}


def action_open_port(port, proto="tcp"):
    """Открыть порт на интерфейс"""
    try:
        port = int(port)
    except:
        return {"error": "Invalid port number"}

    if port in DANGEROUS_PORTS:
        return {"error": f"Port {port} is in dangerous list, cannot open"}

    if port < 1 or port > 65535:
        return {"error": "Port out of range"}

    if proto not in ("tcp", "udp"):
        return {"error": "Invalid protocol"}

    # Вставляем перед правилами DROP в конце
    result = run_cmd(
        f"iptables -I INPUT 5 -i {NET_IF} -p {proto} --dport {port} -j ACCEPT"
    )
    log(f"ACTION: open_port {port}/{proto} -> {result}")
    return {"ok": True, "action": "open_port", "port": port, "proto": proto}


def action_close_port(port, proto="tcp"):
    """Закрыть порт на интерфейс"""
    try:
        port = int(port)
    except:
        return {"error": "Invalid port number"}

    if proto not in ("tcp", "udp"):
        return {"error": "Invalid protocol"}

    result = run_cmd(
        f"iptables -D INPUT -i {NET_IF} -p {proto} --dport {port} -j ACCEPT"
    )
    log(f"ACTION: close_port {port}/{proto} -> {result}")
    return {"ok": True, "action": "close_port", "port": port, "proto": proto}


def handle_action(action, params):
    """Обработка действия"""
    if action not in ALLOWED_ACTIONS:
        return {"error": f"Unknown action: {action}"}

    if action == "block_ip":
        return action_block_ip(params.get("ip", ""))
    elif action == "unblock_ip":
        return action_unblock_ip(params.get("ip", ""))
    elif action == "open_port":
        return action_open_port(params.get("port", ""), params.get("proto", "tcp"))
    elif action == "close_port":
        return action_close_port(params.get("port", ""), params.get("proto", "tcp"))
    elif action == "full_report":
        return collect_all_data()
    elif action == "list_rules":
        return {"iptables": get_iptables_rules()}
    elif action == "list_ports":
        ports = get_listening_ports()
        rules = get_iptables_rules()
        return {"ports": check_port_firewall_status(ports, rules)}
    elif action == "list_docker":
        return {"docker": get_docker_info()}
    elif action == "list_fail2ban":
        return {"fail2ban": get_fail2ban_info()}
    elif action == "system_info":
        return {"system": get_system_info(), "interfaces": get_interfaces()}
    elif action == "list_nat":
        rules = get_iptables_rules()
        return {"nat": rules.get("nat", {})}
    elif action == "list_forward":
        rules = get_iptables_rules()
        return {"forward": rules.get("filter", {}).get("FORWARD", {})}
    elif action == "list_connections":
        return {"connections": get_connections_info()}

    return {"error": "Not implemented"}


# ─── Unix Socket Server ───

class IPTablesRequestHandler(StreamRequestHandler):
    """Обработчик запросов через Unix-сокет"""

    def handle(self):
        try:
            raw = self.rfile.readline(8192).decode("utf-8").strip()
            if not raw:
                self.send_response({"error": "Empty request"})
                return

            request = json.loads(raw)
            action = request.get("action", "full_report")
            params = request.get("params", {})

            # Проверка токена (опционально)
            token = request.get("token", "")

            response = handle_action(action, params)
            self.send_response(response)

        except json.JSONDecodeError:
            self.send_response({"error": "Invalid JSON"})
        except Exception as e:
            log(f"Handler error: {e}")
            self.send_response({"error": str(e)})

    def send_response(self, data):
        try:
            resp = json.dumps(data, ensure_ascii=False, default=str) + "\n"
            self.wfile.write(resp.encode("utf-8"))
            self.wfile.flush()
        except:
            pass


class ThreadedUnixServer(UnixStreamServer):
    """Многопоточный Unix-сокет сервер"""
    allow_reuse_address = True

    def process_request(self, request, client_address):
        t = threading.Thread(target=self.process_request_thread, args=(request, client_address))
        t.daemon = True
        t.start()

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


def cleanup(signum=None, frame=None):
    """Очистка при остановке"""
    log("Shutting down...")
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    if os.path.exists(PID_FILE):
        os.unlink(PID_FILE)
    sys.exit(0)


def main():
    # Cleanup old socket
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    # Write PID
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    # Signal handlers
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    # Start server
    server = ThreadedUnixServer(SOCKET_PATH, IPTablesRequestHandler)
    os.chmod(SOCKET_PATH, 0o660)

    # Даём доступ nginx/php-fpm
    # Группа nginx должна иметь доступ к сокету
    try:
        import grp
        nginx_gid = grp.getgrnam("nginx").gr_gid
        os.chown(SOCKET_PATH, 0, nginx_gid)
    except:
        # Если нет группы nginx, ставим 666
        os.chmod(SOCKET_PATH, 0o666)

    log(f"Started on {SOCKET_PATH} (PID: {os.getpid()})")
    print(f"iptables-manager API listening on {SOCKET_PATH}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()