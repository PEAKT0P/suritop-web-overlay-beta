<?php
/**
 * /var/www/router.denjik.ru/htdocs/admin_stats.php
 * v3.2 - Pure Data Edition + API Ban Integration (No Map, No Sound)
 */
require_once __DIR__ . '/config.php';

function getStatsDB() {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO(
            "mysql:host=" . STATS_DB_HOST . ";dbname=" . STATS_DB_NAME . ";charset=utf8mb4",
            STATS_DB_USER, STATS_DB_PASS,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
        );
    }
    return $pdo;
}

$pdo = getStatsDB();

// ── API ЭНДПОИНТЫ (ЧТЕНИЕ ИЗ БД) ──
if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');

    $date = $_GET['date'] ?? date('Y-m-d');
    $ip = $_GET['ip'] ?? '';
    $port = $_GET['port'] ?? '';
    $all_time = ($_GET['all_time'] ?? 'false') === 'true';

    $w_ipt = "1=1"; $w_waf = "1=1"; $w_ids = "1=1";
    $p_ipt = []; $p_waf = []; $p_ids = [];

    if (!$all_time) {
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
            $w_ipt .= " AND DATE(logged_at) = ?"; $p_ipt[] = $date;
            $w_waf .= " AND DATE(logged_at) = ?"; $p_waf[] = $date;
            $w_ids .= " AND DATE(logged_at) = ?"; $p_ids[] = $date;
        }
    }
    if ($ip) {
        $w_ipt .= " AND src_ip LIKE ?"; $p_ipt[] = "%$ip%";
        $w_waf .= " AND src_ip LIKE ?"; $p_waf[] = "%$ip%";
        $w_ids .= " AND src_ip LIKE ?"; $p_ids[] = "%$ip%";
    }
    if ($port) {
        $w_ipt .= " AND dst_port = ?"; $p_ipt[] = $port;
        $w_waf .= " AND 1=0";
        $w_ids .= " AND dst_port = ?"; $p_ids[] = $port;
    }

    if ($_GET['api'] === 'day_stats') {
        $result = [];

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM ipt_drops WHERE $w_ipt");
        $stmt->execute($p_ipt); $result['total_drops'] = $stmt->fetchColumn();

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM waf_blocks WHERE $w_waf");
        $stmt->execute($p_waf); $result['total_waf'] = $stmt->fetchColumn();

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM suricata_alerts WHERE $w_ids");
        $stmt->execute($p_ids); $result['total_ids'] = $stmt->fetchColumn();

        // Уникальные IP-адреса
        $sql_unique = "SELECT COUNT(DISTINCT src_ip) FROM (
            SELECT src_ip FROM ipt_drops WHERE $w_ipt
            UNION SELECT src_ip FROM waf_blocks WHERE $w_waf
            UNION SELECT src_ip FROM suricata_alerts WHERE $w_ids
        ) as u";
        $stmt = $pdo->prepare($sql_unique);
        $stmt->execute(array_merge($p_ipt, $p_waf, $p_ids));
        $result['unique_ips'] = $stmt->fetchColumn();

        // Сводный топ
        $sql_top = "
            SELECT src_ip, COUNT(*) as total_events, MAX(max_source) as max_source, country FROM (
                SELECT src_ip, 'IPTables' as max_source FROM ipt_drops WHERE $w_ipt
                UNION ALL SELECT src_ip, 'WAF' as max_source FROM waf_blocks WHERE $w_waf
                UNION ALL SELECT src_ip, 'Suricata' as max_source FROM suricata_alerts WHERE $w_ids
            ) as combined
            LEFT JOIN geo_cache g ON combined.src_ip = g.ip
            GROUP BY src_ip, country
            ORDER BY total_events DESC LIMIT 150
        ";
        $stmt = $pdo->prepare($sql_top);
        $stmt->execute(array_merge($p_ipt, $p_waf, $p_ids));
        $result['top_attackers'] = $stmt->fetchAll();

        echo json_encode($result); exit;
    }

    if ($_GET['api'] === 'ip_details') {
        $req_ip = $_GET['req_ip'] ?? '';
        $timeline = [];

        $w_ipt_ip = $w_ipt . " AND src_ip = ?"; $p_ipt_ip = array_merge($p_ipt, [$req_ip]);
        $w_waf_ip = $w_waf . " AND src_ip = ?"; $p_waf_ip = array_merge($p_waf, [$req_ip]);
        $w_ids_ip = $w_ids . " AND src_ip = ?"; $p_ids_ip = array_merge($p_ids, [$req_ip]);

        $stmt = $pdo->prepare("SELECT 'IPTables' as type, CONCAT('Блок порта: ', dst_port) as info, DATE_FORMAT(logged_at, '%Y-%m-%d %H:%i:%s') as time, 'critical' as severity FROM ipt_drops WHERE $w_ipt_ip ORDER BY logged_at DESC LIMIT 50");
        $stmt->execute($p_ipt_ip); $timeline = array_merge($timeline, $stmt->fetchAll());

        $stmt = $pdo->prepare("SELECT 'WAF' as type, CONCAT('[', host, '] ', method, ' ', uri) as info, DATE_FORMAT(logged_at, '%Y-%m-%d %H:%i:%s') as time, rule_msg as severity FROM waf_blocks WHERE $w_waf_ip ORDER BY logged_at DESC LIMIT 50");
        $stmt->execute($p_waf_ip); $timeline = array_merge($timeline, $stmt->fetchAll());

        $stmt = $pdo->prepare("SELECT 'Suricata' as type, sig_msg as info, DATE_FORMAT(logged_at, '%Y-%m-%d %H:%i:%s') as time, CONCAT('Sev: ', severity) as severity FROM suricata_alerts WHERE $w_ids_ip ORDER BY logged_at DESC LIMIT 50");
        $stmt->execute($p_ids_ip); $timeline = array_merge($timeline, $stmt->fetchAll());

        usort($timeline, function($a, $b) { return strcmp($b['time'], $a['time']); });
        echo json_encode($timeline); exit;
    }
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>🛡️ Security Data Center</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">

    <style>
        :root {
            --bg-main: #0f172a; --bg-panel: #1e293b; --bg-card: #334155;
            --text-main: #f8fafc; --text-muted: #94a3b8; --border-color: #475569;
            --accent-red: #ef4444; --accent-orange: #f59e0b; --accent-blue: #3b82f6; --accent-purple: #a855f7; --accent-green: #10b981;
            --font-mono: 'JetBrains Mono', monospace;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: var(--bg-main); color: var(--text-main); font-family: 'Inter', sans-serif; padding: 15px; font-size: 13px; }

        /* Toolbar & Controls */
        .toolbar {
            display: flex; flex-wrap: wrap; gap: 15px; justify-content: space-between; align-items: center;
            background: var(--bg-panel); padding: 15px; border-radius: 8px; margin-bottom: 15px; border: 1px solid var(--border-color);
        }
        .filter-group { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }

        .date-nav { display: flex; align-items: center; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 4px; overflow: hidden; }
        .btn-nav { background: transparent; color: var(--text-muted); border: none; padding: 6px 12px; cursor: pointer; font-weight: bold; transition: 0.2s; }
        .btn-nav:hover { background: rgba(255,255,255,0.1); color: #fff; }

        input[type="date"], input[type="text"] {
            background: transparent; color: var(--text-main); border: none; border-left: 1px solid var(--border-color); border-right: 1px solid var(--border-color);
            padding: 6px 10px; font-family: var(--font-mono); outline: none; width: 130px;
        }
        input[type="text"] { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 4px; }
        input[type="date"]::-webkit-calendar-picker-indicator { filter: invert(1); cursor: pointer; }

        .checkbox-lbl { display: flex; align-items: center; gap: 5px; cursor: pointer; color: var(--accent-orange); font-weight: 600; margin-left: 10px;}

        .stats-summary { display: flex; flex-wrap: wrap; gap: 10px; }
        .stat-badge { background: var(--bg-card); padding: 6px 10px; border-radius: 6px; border-left: 3px solid var(--border-color); font-weight: 600; font-size: 12px; display: flex; gap: 6px;}
        .stat-badge.drops { border-color: var(--accent-red); }
        .stat-badge.waf { border-color: var(--accent-orange); }
        .stat-badge.ids { border-color: var(--accent-purple); }
        .stat-badge.uniq { border-color: var(--accent-blue); }

        /* Table */
        .panel { background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; }
        .panel-header { padding: 12px 15px; border-bottom: 1px solid var(--border-color); font-weight: 700; color: var(--text-muted); }
        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 600px; }
        th, td { padding: 12px 15px; border-bottom: 1px solid rgba(255,255,255,0.05); text-align: left; }
        th { background: rgba(0,0,0,0.2); color: var(--text-muted); font-weight: 600; }
        .attacker-row { cursor: pointer; transition: background 0.1s; }
        .attacker-row:hover { background: rgba(255,255,255,0.05); }

        .mono { font-family: var(--font-mono); }

        .copy-btn { background: transparent; border: none; color: var(--text-muted); cursor: pointer; font-size: 14px; margin-left: 8px; padding: 2px; }
        .copy-btn:hover { color: var(--accent-blue); }

        /* Log Details & API Actions */
        .detail-wrapper { background: #090d16; padding: 15px; border-left: 3px solid var(--accent-blue); }

        .cli-actions { margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px dashed var(--border-color); display: flex; gap: 10px; flex-wrap: wrap; align-items: center;}
        .cli-code { background: rgba(0,0,0,0.4); padding: 6px 10px; border-radius: 4px; border: 1px solid var(--border-color); font-size: 12px; font-weight: 600; cursor: pointer; color: var(--text-muted); transition: 0.2s;}
        .cli-code:hover { border-color: var(--accent-blue); color: var(--accent-blue); }
        .cli-code.action-ban { color: var(--accent-red); border-color: rgba(239, 68, 68, 0.4); background: rgba(239, 68, 68, 0.1); }
        .cli-code.action-ban:hover { border-color: var(--accent-red); background: rgba(239, 68, 68, 0.2); }

        .timeline-item { display: flex; flex-wrap: wrap; gap: 10px; padding: 6px 0; border-bottom: 1px dotted rgba(255,255,255,0.05); font-size: 11px; }
        .timeline-time { color: var(--text-muted); width: 120px; flex-shrink: 0;}
        .timeline-type { width: 70px; font-weight: 600; flex-shrink: 0;}
        .timeline-type.IPTables { color: var(--accent-red); }
        .timeline-type.WAF { color: var(--accent-orange); }
        .timeline-type.Suricata { color: var(--accent-purple); }
        .timeline-info { flex-grow: 1; color: #e2e8f0; min-width: 200px; }

        /* Toast Notification */
        #toast { position: fixed; bottom: 20px; right: 20px; background: var(--accent-green); color: #fff; padding: 10px 20px; border-radius: 6px; font-weight: bold; opacity: 0; transition: opacity 0.3s; pointer-events: none; z-index: 1000; box-shadow: 0 4px 12px rgba(0,0,0,0.3);}

        @media (max-width: 768px) {
            .filter-group input[type="text"] { width: 100%; }
            .toolbar { flex-direction: column; align-items: flex-start; }
            .date-nav { width: 100%; justify-content: space-between; }
            .date-nav input { flex-grow: 1; text-align: center; }
        }
    </style>
</head>
<body>

<div class="toolbar">
    <div class="filter-group">
        <div class="date-nav">
            <button class="btn-nav" onclick="changeDate(-1)" title="Предыдущий день">◀</button>
            <input type="date" id="filterDate" value="<?= date('Y-m-d') ?>" onchange="fetchStats()">
            <button class="btn-nav" onclick="changeDate(1)" title="Следующий день">▶</button>
        </div>
        <input type="text" id="filterIp" placeholder="IP или подсеть..." title="Поддерживает неполный ввод, например 192.168." oninput="debounceFetch()">
        <input type="text" id="filterPort" placeholder="Порт..." oninput="debounceFetch()">
        <label class="checkbox-lbl">
            <input type="checkbox" id="filterAllTime" onchange="fetchStats()"> За всё время
        </label>
    </div>

    <div class="stats-summary">
        <div class="stat-badge uniq">Хостов: <span id="sumUniq" class="mono">0</span></div>
        <div class="stat-badge drops">IPT: <span id="sumDrops" class="mono">0</span></div>
        <div class="stat-badge waf">WAF: <span id="sumWaf" class="mono">0</span></div>
        <div class="stat-badge ids">IDS: <span id="sumIds" class="mono">0</span></div>
    </div>
</div>

<div class="panel">
    <div class="panel-header">Журнал Атакующих</div>
    <div class="table-responsive">
        <table>
            <thead>
                <tr>
                    <th style="width: 30px;"></th>
                    <th>IP-адрес</th>
                    <th>Страна</th>
                    <th>Инцидентов</th>
                    <th>Вектор</th>
                </tr>
            </thead>
            <tbody id="attackerTable">
                <tr><td colspan="5">Сбор данных...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div id="toast">Действие выполнено</div>

<script>
    let fetchTimer;
    let csrfToken = '';

    // Инициализация: получаем CSRF токен для API
    async function initApi() {
        try {
            const res = await fetch('iptables/api.php?action=csrf_token');
            const data = await res.json();
            if (data.token) {
                csrfToken = data.token;
            }
        } catch (e) {
            console.error("API CSRF Error:", e);
        }
    }

    function showToast(text, isError = false) {
        const toast = document.getElementById('toast');
        toast.textContent = text;
        toast.style.backgroundColor = isError ? 'var(--accent-red)' : 'var(--accent-green)';
        toast.style.opacity = 1;
        setTimeout(() => toast.style.opacity = 0, 3000);
    }

    // Вызов боевого API для блокировки IP
    async function execBanIp(ip, event) {
        if (event) event.stopPropagation();
        if (!csrfToken) {
            showToast("Ошибка: CSRF токен не загружен", true);
            return;
        }

        if (!confirm(`Вы уверены, что хотите ЗАБЛОКИРОВАТЬ IP ${ip} через iptables?`)) {
            return;
        }

        try {
            const res = await fetch('iptables/api.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'block_ip',
                    params: { ip: ip },
                    csrf: csrfToken
                })
            });
            const data = await res.json();

            if (data.error) {
                showToast('Ошибка API: ' + data.error, true);
            } else if (data.ok) {
                showToast(`✅ IP ${ip} успешно забанен!`);
            } else {
                showToast('Неизвестный ответ сервера', true);
            }
        } catch(e) {
            showToast('Ошибка сети при выполнении бана', true);
        }
    }

    function debounceFetch() {
        clearTimeout(fetchTimer);
        fetchTimer = setTimeout(fetchStats, 400);
    }

    function changeDate(offset) {
        const input = document.getElementById('filterDate');
        let d = new Date(input.value);
        if (isNaN(d.getTime())) d = new Date();
        d.setDate(d.getDate() + offset);
        input.value = d.toISOString().split('T')[0];
        document.getElementById('filterAllTime').checked = false;
        fetchStats();
    }

    function copyToClipboard(text, event) {
        if(event) event.stopPropagation();
        navigator.clipboard.writeText(text).then(() => {
            showToast(text + ' скопирован');
        });
    }

    async function fetchStats() {
        const date = document.getElementById('filterDate').value;
        const ip = document.getElementById('filterIp').value.trim();
        const port = document.getElementById('filterPort').value.trim();
        const allTime = document.getElementById('filterAllTime').checked;

        try {
            const url = `?api=day_stats&date=${date}&ip=${ip}&port=${port}&all_time=${allTime}`;
            const res = await fetch(url);
            const data = await res.json();

            document.getElementById('sumDrops').textContent = data.total_drops || 0;
            document.getElementById('sumWaf').textContent = data.total_waf || 0;
            document.getElementById('sumIds').textContent = data.total_ids || 0;
            document.getElementById('sumUniq').textContent = data.unique_ips || 0;

            const tbody = document.getElementById('attackerTable');
            tbody.innerHTML = '';

            if(data.top_attackers && data.top_attackers.length > 0) {
                data.top_attackers.forEach((row) => {
                    const safeId = replaceDot(row.src_ip);
                    tbody.innerHTML += `
                        <tr class="attacker-row" onclick="toggleIPDetails('${escapeHtml(row.src_ip)}', this)">
                            <td class="mono" style="color: var(--text-muted); text-align:center;">▶</td>
                            <td class="mono" style="font-weight:600; color:var(--accent-blue);">
                                ${escapeHtml(row.src_ip)}
                                <button class="copy-btn" onclick="copyToClipboard('${escapeHtml(row.src_ip)}', event)" title="Скопировать IP">📋</button>
                            </td>
                            <td>${escapeHtml(row.country || 'Локальный')}</td>
                            <td class="mono">${row.total_events}</td>
                            <td><span class="mono" style="font-size:11px; padding:2px 6px; background:rgba(255,255,255,0.05); border-radius:3px; border:1px solid var(--border-color);">${row.max_source}</span></td>
                        </tr>
                        <tr id="details-${safeId}" style="display:none; background:#090d16;">
                            <td colspan="5"><div class="detail-wrapper" id="content-${safeId}">Загрузка...</div></td>
                        </tr>
                    `;
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="5">По заданным фильтрам данных нет.</td></tr>';
            }
        } catch (e) { console.error(e); }
    }

    async function toggleIPDetails(ip, rowElement) {
        const date = document.getElementById('filterDate').value;
        const allTime = document.getElementById('filterAllTime').checked;
        const safeId = replaceDot(ip);
        const detailRow = document.getElementById(`details-${safeId}`);
        const contentDiv = document.getElementById(`content-${safeId}`);
        const indicator = rowElement.querySelector('td');

        if(detailRow.style.display === 'table-row') {
            detailRow.style.display = 'none'; indicator.textContent = '▶'; return;
        }

        detailRow.style.display = 'table-row'; indicator.textContent = '▼';
        try {
            const url = `?api=ip_details&req_ip=${ip}&date=${date}&all_time=${allTime}`;
            const res = await fetch(url);
            const logs = await res.json();

            // API Action Buttons
            let html = `
                <div class="cli-actions">
                    <button class="cli-code action-ban mono" onclick="execBanIp('${ip}', event)" title="Заблокировать через демона iptables">🚨 BAN IP (API)</button>
                    <span style="color:var(--text-muted); font-size: 11px; margin-left: 10px; margin-right: 5px;">CLI Команды:</span>
                    <span class="cli-code mono" onclick="copyToClipboard('fail2ban-client set recidive banip ${ip}', event)" title="Скопировать команду fail2ban">Copy f2b</span>
                    <span class="cli-code mono" onclick="copyToClipboard('whois ${ip}', event)">whois</span>
                </div>
            `;

            if(logs.length > 0) {
                logs.forEach(log => {
                    html += `
                        <div class="timeline-item">
                            <span class="timeline-time mono">${escapeHtml(log.time)}</span>
                            <span class="timeline-type ${log.type}">${escapeHtml(log.type)}</span>
                            <span class="timeline-info mono">${escapeHtml(log.info)}
                                <span style="color:var(--text-muted); font-size:10px;"> // ${escapeHtml(log.severity)}</span>
                            </span>
                        </div>
                    `;
                });
            } else {
                html += '<div style="color:var(--text-muted)">Нет детальной истории.</div>';
            }
            contentDiv.innerHTML = html;
        } catch(e) { contentDiv.innerHTML = '<div style="color:var(--accent-red)">Ошибка загрузки таймлайна.</div>'; }
    }

    function replaceDot(ip) { return ip.replace(/\./g, '_').replace(/:/g, '_'); }
    function escapeHtml(str) { return (str||'').toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

    document.addEventListener("DOMContentLoaded", () => {
        initApi(); // Загружаем CSRF токен
        fetchStats();
    });
</script>
</body>
</html>