<?php
/**
 * /var/www/router.denjik.ru/htdocs/attack_map.php  v9.1 (Design v3.2 Fixed Dark Map)
 * Карта атак — реалтайм + воспроизведение (с кешем)
 * v8: UI V3 — Glassmorphism, Топографическая тема
 * v9: Fixes — Драг-н-дроп панелей, фикс тултипов
 * v9.1: Fixes — Возвращаем видимость ландшафта в темной теме (настройка CSS фильтров)
 * v9.2: CYBER RADIO INTEGRATION — Сонификация трафика (FSK модуляция)
 */

require_once __DIR__ . '/../config.php';

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

// ── Кеш воспроизведения ──
function buildReplayCache() {
    $pdo = getStatsDB();
    $rows = $pdo->query("
        SELECT d.src_ip AS ip, d.dst_port AS port, d.logged_at AS time,
               g.lat, g.lon, g.country, 'ipt' AS src
        FROM ipt_drops d
        JOIN geo_cache g ON d.src_ip = g.ip
        WHERE g.lat IS NOT NULL AND g.lat != 0
        ORDER BY d.logged_at DESC
        LIMIT 3000
    ")->fetchAll();
    $json = json_encode(['attacks' => $rows, 'total' => count($rows), 'cached_at' => date('Y-m-d H:i:s')], JSON_UNESCAPED_UNICODE);
    file_put_contents(CACHE_FILE, $json);
    return $json;
}

function getReplayCache() {
    if (file_exists(CACHE_FILE) && (time() - filemtime(CACHE_FILE)) < CACHE_TTL) {
        return file_get_contents(CACHE_FILE);
    }
    return buildReplayCache();
}

$pdo = getStatsDB();

// ── API Endpoints ──
if (isset($_GET['replay_cache'])) { header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: public, max-age=120'); echo getReplayCache(); exit; }
if (isset($_GET['rebuild_cache'])) { buildReplayCache(); echo "OK: cache rebuilt\n"; exit; }

if (isset($_GET['all_geo'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: public, max-age=60');
    $rows = $pdo->query("SELECT g.ip, g.lat, g.lon, g.country, COUNT(d.id) AS attacks, GROUP_CONCAT(DISTINCT d.dst_port ORDER BY d.dst_port SEPARATOR ',') AS ports FROM geo_cache g JOIN ipt_drops d ON d.src_ip = g.ip WHERE g.lat IS NOT NULL AND g.lat != 0 GROUP BY g.ip, g.lat, g.lon, g.country ORDER BY attacks DESC LIMIT 2000")->fetchAll();
    echo json_encode(['points' => $rows], JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['attacks'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: no-cache');
    $since = $_GET['since'] ?? null; $limit = min((int)($_GET['limit'] ?? 100), 500);
    if ($since) {
        $stmt = $pdo->prepare("SELECT d.src_ip AS ip, d.dst_port AS port, d.logged_at AS time, g.lat, g.lon, g.country FROM ipt_drops d LEFT JOIN geo_cache g ON d.src_ip=g.ip WHERE d.logged_at > :since AND d.logged_at <= NOW() AND g.lat IS NOT NULL AND g.lat!=0 ORDER BY d.logged_at ASC LIMIT :lim");
        $stmt->bindValue(':since', $since); $stmt->bindValue(':lim', $limit, PDO::PARAM_INT); $stmt->execute();
    } else {
        $stmt = $pdo->prepare("SELECT d.src_ip AS ip, d.dst_port AS port, d.logged_at AS time, g.lat, g.lon, g.country FROM ipt_drops d LEFT JOIN geo_cache g ON d.src_ip=g.ip WHERE g.lat IS NOT NULL AND g.lat!=0 AND d.logged_at <= NOW() ORDER BY d.logged_at DESC LIMIT :lim");
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT); $stmt->execute();
    }
    echo json_encode(['attacks' => $stmt->fetchAll()], JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['stats'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: public, max-age=20');
    $s = [];
    $s['today_drops']  = (int)$pdo->query("SELECT COUNT(*) FROM ipt_drops WHERE logged_at >= CURDATE()")->fetchColumn();
    $s['today_ips']    = (int)$pdo->query("SELECT COUNT(DISTINCT src_ip) FROM ipt_drops WHERE logged_at >= CURDATE()")->fetchColumn();
    $s['today_bans']   = (int)$pdo->query("SELECT COUNT(*) FROM f2b_actions WHERE action='ban' AND logged_at >= CURDATE()")->fetchColumn();
    $s['total_drops']  = (int)$pdo->query("SELECT COUNT(*) FROM ipt_drops")->fetchColumn();
    $s['total_bans']   = (int)$pdo->query("SELECT COUNT(*) FROM f2b_actions WHERE action='ban'")->fetchColumn();
    $s['geo_cached']   = (int)$pdo->query("SELECT COUNT(*) FROM geo_cache WHERE lat IS NOT NULL")->fetchColumn();
    $s['cpu_temp']     = (float)($pdo->query("SELECT temp_c FROM cpu_temp ORDER BY recorded_at DESC LIMIT 1")->fetchColumn() ?: 0);
    $s['week_drops']   = (int)$pdo->query("SELECT COUNT(*) FROM ipt_drops WHERE logged_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)")->fetchColumn();
    $s['yesterday_drops'] = (int)$pdo->query("SELECT COUNT(*) FROM ipt_drops WHERE DATE(logged_at) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)")->fetchColumn();
    $s['nginx_blocks'] = (int)$pdo->query("SELECT COUNT(*) FROM nginx_blocks WHERE logged_at >= CURDATE()")->fetchColumn();

    try { $s['today_ssh'] = (int)$pdo->query("SELECT COUNT(*) FROM ssh_attacks WHERE logged_at >= CURDATE()")->fetchColumn(); } catch(Exception $e) { $s['today_ssh']=0; }
    try { $s['today_nc_auth'] = (int)$pdo->query("SELECT COUNT(*) FROM nc_auth_fails WHERE logged_at >= CURDATE()")->fetchColumn(); } catch(Exception $e) { $s['today_nc_auth']=0; }
    try { $s['today_waf'] = (int)$pdo->query("SELECT COUNT(*) FROM waf_blocks WHERE logged_at >= CURDATE()")->fetchColumn(); } catch(Exception $e) { $s['today_waf']=0; }
    try { $s['today_ids'] = (int)$pdo->query("SELECT COUNT(*) FROM suricata_alerts WHERE logged_at >= CURDATE()")->fetchColumn(); } catch(Exception $e) { $s['today_ids']=0; }
    try { $s['conntrack'] = (int)($pdo->query("SELECT connections FROM conntrack_stats ORDER BY recorded_at DESC LIMIT 1")->fetchColumn() ?: 0); } catch(Exception $e) { $s['conntrack']=0; }

    try {
        $row = $pdo->query("SELECT load_1m, ram_used_mb, ram_total_mb FROM system_load ORDER BY recorded_at DESC LIMIT 1")->fetch();
        if ($row) { $s['load_1m'] = (float)$row['load_1m']; $s['ram_used_mb'] = (float)$row['ram_used_mb']; $s['ram_total_mb'] = (float)$row['ram_total_mb']; }
    } catch(Exception $e) {}
    try {
        $row = $pdo->query("SELECT rx_mbytes_s, tx_mbytes_s FROM net_traffic ORDER BY recorded_at DESC LIMIT 1")->fetch();
        if ($row) { $s['rx_mbps'] = (float)$row['rx_mbytes_s']; $s['tx_mbps'] = (float)$row['tx_mbytes_s']; }
    } catch(Exception $e) {}

    echo json_encode($s, JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['countries'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: public, max-age=60');
    $rows = $pdo->query("SELECT g.country, COUNT(*) AS cnt, COUNT(DISTINCT d.src_ip) AS ips FROM ipt_drops d JOIN geo_cache g ON d.src_ip=g.ip WHERE g.country IS NOT NULL AND g.country!='' GROUP BY g.country ORDER BY cnt DESC LIMIT 20")->fetchAll();
    echo json_encode(['countries' => $rows], JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['hourly'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: public, max-age=120');
    $rows = $pdo->query("SELECT DATE_FORMAT(logged_at, '%Y-%m-%d %H') AS hkey, HOUR(logged_at) AS h, COUNT(*) AS cnt FROM ipt_drops WHERE logged_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY hkey ORDER BY hkey")->fetchAll();
    echo json_encode(['hourly' => $rows], JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['ports'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: public, max-age=60');
    $rows = $pdo->query("SELECT dst_port AS port, COUNT(*) AS cnt FROM ipt_drops WHERE logged_at >= CURDATE() GROUP BY dst_port ORDER BY cnt DESC LIMIT 10")->fetchAll();
    echo json_encode(['ports' => $rows], JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['ssh'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: public, max-age=60');
    $result = [];
    try {
        $result['top_users'] = $pdo->query("SELECT username, COUNT(*) AS cnt FROM ssh_attacks WHERE logged_at >= CURDATE() GROUP BY username ORDER BY cnt DESC LIMIT 15")->fetchAll();
        $result['top_ips'] = $pdo->query("SELECT s.src_ip AS ip, COUNT(*) AS cnt, g.country FROM ssh_attacks s LEFT JOIN geo_cache g ON s.src_ip = g.ip WHERE s.logged_at >= CURDATE() GROUP BY s.src_ip, g.country ORDER BY cnt DESC LIMIT 10")->fetchAll();
        $result['total_today'] = (int)$pdo->query("SELECT COUNT(*) FROM ssh_attacks WHERE logged_at >= CURDATE()")->fetchColumn();
    } catch(Exception $e) { $result['error'] = $e->getMessage(); }
    echo json_encode($result, JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['metrics'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: public, max-age=30');
    $result = [];
    try {
        $result['traffic'] = $pdo->query("SELECT DATE_FORMAT(recorded_at, '%H:%i') AS t, rx_mbytes_s AS rx, tx_mbytes_s AS tx FROM net_traffic WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) ORDER BY recorded_at")->fetchAll();
        $result['conntrack'] = $pdo->query("SELECT DATE_FORMAT(recorded_at, '%H:%i') AS t, connections AS c FROM conntrack_stats WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) ORDER BY recorded_at")->fetchAll();
        $result['load'] = $pdo->query("SELECT DATE_FORMAT(recorded_at, '%H:%i') AS t, load_1m AS l1, load_5m AS l5, ram_used_mb AS ram FROM system_load WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) ORDER BY recorded_at")->fetchAll();
        $result['temp'] = $pdo->query("SELECT DATE_FORMAT(recorded_at, '%H:%i') AS t, temp_c AS temp FROM cpu_temp WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) ORDER BY recorded_at")->fetchAll();
    } catch(Exception $e) { $result['error'] = $e->getMessage(); }
    echo json_encode($result, JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['timeline'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: public, max-age=120');
    $result = [];
    try {
        $result['ipt'] = $pdo->query("SELECT HOUR(logged_at) AS h, COUNT(*) AS cnt FROM ipt_drops WHERE logged_at >= CURDATE() GROUP BY h ORDER BY h")->fetchAll();
        $result['f2b'] = $pdo->query("SELECT HOUR(logged_at) AS h, COUNT(*) AS cnt FROM f2b_actions WHERE action='ban' AND logged_at >= CURDATE() GROUP BY h ORDER BY h")->fetchAll();
        $result['nginx'] = $pdo->query("SELECT HOUR(logged_at) AS h, COUNT(*) AS cnt FROM nginx_blocks WHERE logged_at >= CURDATE() GROUP BY h ORDER BY h")->fetchAll();
        try { $result['ssh'] = $pdo->query("SELECT HOUR(logged_at) AS h, COUNT(*) AS cnt FROM ssh_attacks WHERE logged_at >= CURDATE() GROUP BY h ORDER BY h")->fetchAll(); } catch(Exception $e) { $result['ssh'] = []; }
        try { $result['ids'] = $pdo->query("SELECT HOUR(logged_at) AS h, COUNT(*) AS cnt FROM suricata_alerts WHERE logged_at >= CURDATE() GROUP BY h ORDER BY h")->fetchAll(); } catch(Exception $e) { $result['ids'] = []; }
    } catch(Exception $e) { $result['error'] = $e->getMessage(); }
    echo json_encode($result, JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['waf'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: no-cache');
    $result = [];
    try {
        $since = $_GET['since'] ?? null; $limit = min((int)($_GET['limit'] ?? 30), 200);
        if ($since) {
            $stmt = $pdo->prepare("SELECT w.src_ip AS ip, w.host, w.uri, w.method, w.rule_id, w.rule_msg, w.status_code, w.logged_at AS time, g.lat, g.lon, g.country FROM waf_blocks w LEFT JOIN geo_cache g ON w.src_ip = g.ip WHERE w.logged_at > :since ORDER BY w.logged_at ASC LIMIT :lim");
            $stmt->bindValue(':since', $since); $stmt->bindValue(':lim', $limit, PDO::PARAM_INT); $stmt->execute();
        } else {
            $stmt = $pdo->prepare("SELECT w.src_ip AS ip, w.host, w.uri, w.method, w.rule_id, w.rule_msg, w.status_code, w.logged_at AS time, g.lat, g.lon, g.country FROM waf_blocks w LEFT JOIN geo_cache g ON w.src_ip = g.ip ORDER BY w.logged_at DESC LIMIT :lim");
            $stmt->bindValue(':lim', $limit, PDO::PARAM_INT); $stmt->execute();
        }
        $result['attacks'] = $stmt->fetchAll();
        $result['today'] = (int)$pdo->query("SELECT COUNT(*) FROM waf_blocks WHERE logged_at >= CURDATE()")->fetchColumn();
        $result['top_rules'] = $pdo->query("SELECT rule_id, rule_msg, COUNT(*) AS cnt FROM waf_blocks WHERE logged_at >= CURDATE() GROUP BY rule_id, rule_msg ORDER BY cnt DESC LIMIT 10")->fetchAll();
    } catch(Exception $e) { $result['error'] = $e->getMessage(); }
    echo json_encode($result, JSON_UNESCAPED_UNICODE); exit;
}

if (isset($_GET['ids'])) {
    header('Content-Type: application/json; charset=utf-8'); header('Access-Control-Allow-Origin: *'); header('Cache-Control: no-cache');
    $result = [];
    try {
        $since = $_GET['since'] ?? null; $limit = min((int)($_GET['limit'] ?? 30), 200);
        if ($since) {
            $stmt = $pdo->prepare("SELECT s.src_ip AS ip, s.dst_port AS port, s.proto, s.sig_id, s.sig_msg, s.category, s.severity, s.action, s.logged_at AS time, g.lat, g.lon, g.country FROM suricata_alerts s LEFT JOIN geo_cache g ON s.src_ip = g.ip WHERE s.logged_at > :since ORDER BY s.logged_at ASC LIMIT :lim");
            $stmt->bindValue(':since', $since); $stmt->bindValue(':lim', $limit, PDO::PARAM_INT); $stmt->execute();
        } else {
            $stmt = $pdo->prepare("SELECT s.src_ip AS ip, s.dst_port AS port, s.proto, s.sig_id, s.sig_msg, s.category, s.severity, s.action, s.logged_at AS time, g.lat, g.lon, g.country FROM suricata_alerts s LEFT JOIN geo_cache g ON s.src_ip = g.ip ORDER BY s.logged_at DESC LIMIT :lim");
            $stmt->bindValue(':lim', $limit, PDO::PARAM_INT); $stmt->execute();
        }
        $result['attacks'] = $stmt->fetchAll();
        $result['today'] = (int)$pdo->query("SELECT COUNT(*) FROM suricata_alerts WHERE logged_at >= CURDATE()")->fetchColumn();
        $result['top_sigs'] = $pdo->query("SELECT sig_id, sig_msg, COUNT(*) AS cnt FROM suricata_alerts WHERE logged_at >= CURDATE() GROUP BY sig_id, sig_msg ORDER BY cnt DESC LIMIT 10")->fetchAll();
    } catch(Exception $e) { $result['error'] = $e->getMessage(); }
    echo json_encode($result, JSON_UNESCAPED_UNICODE); exit;
}

// ═══════════════════════════════════════════
// UI V3.2 (Fixed Dark Landscape Contrast)
// ═══════════════════════════════════════════
?>
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>⚔ THREAT MAP — Server Defense V3.2</title>
<script>
(function(){
    try{
        const t = localStorage.getItem('atk_theme') || 'dark';
        document.documentElement.setAttribute('data-theme', t);
    }catch(e){}
})();
</script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Orbitron:wght@400;600;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}

/* ================== DARK THEME (Default) ================== */
:root{
    /* ФИКС ФОНА: Чуть светлее, чтобы не сливалось в бездну */
    --bg:#0d1117;
    --pn:rgba(15, 23, 42, 0.65);
    --gl-blur: blur(12px);
    --pb:rgba(255,255,255,.1);
    --gl:rgba(255,50,50,.25);

    --red:#ff3b30;
    --rdd:#d32f2f;
    --rg:rgba(255,50,50,.5);
    --ora:#ff9500;
    --cy:#32ade6;
    --gn:#34c759;
    --yl:#ffcc00;
    --pu:#af52de;

    --tx:#e2e8f0;
    --dm:#94a3b8; /* Чуть ярче для читаемости */
    --fm:'Share Tech Mono','JetBrains Mono',monospace;
    --fd:'Orbitron',sans-serif;

    --panel-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
}

/* ================== LIGHT THEME (Landscape) ================== */
:root[data-theme="light"]{
    --bg:#f1f5f9;
    --pn:rgba(255, 255, 255, 0.75);
    --pb:rgba(15, 23, 42, 0.12);
    --gl:rgba(15, 23, 42, 0.1);

    --red:#dc2626;
    --rdd:#991b1b;
    --rg:rgba(220, 38, 38, 0.4);
    --ora:#d97706;
    --cy:#0284c7;
    --gn:#16a34a;
    --yl:#ca8a04;
    --pu:#7e22ce;

    --tx:#0f172a;
    --dm:#475569;

    --panel-shadow: 0 8px 32px rgba(30, 41, 59, 0.15);
}

:root[data-theme="light"] body{background:var(--bg)}
:root[data-theme="light"] #map{background:#e2e8f0}
:root[data-theme="light"] .scan{background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(255,255,255,.1) 2px,rgba(255,255,255,.1) 4px); opacity: 0.5;}
:root[data-theme="light"] .leaflet-control-attribution{background:var(--pn)!important; backdrop-filter: var(--gl-blur); color: var(--dm)!important;}
:root[data-theme="light"] .leaflet-control-zoom a{background:var(--pn)!important; backdrop-filter: var(--gl-blur); border-color: var(--pb)!important; color: var(--tx)!important;}
:root[data-theme="light"] .leaflet-control-zoom a:hover{background:rgba(255,255,255,0.9)!important;}
:root[data-theme="light"] .lo{background:var(--bg)}
:root[data-theme="light"] .le{background:rgba(220,38,38,.06)}
:root[data-theme="light"] .le:hover{background:rgba(220,38,38,.12)}
:root[data-theme="light"] .le.fr{background:rgba(217,119,6,.08)}
:root[data-theme="light"] .le.ssh{background:rgba(2,132,199,.08)}
:root[data-theme="light"] .le.nc{background:rgba(126,34,206,.08)}
:root[data-theme="light"] .cb{background:rgba(255,255,255,.5); border-color:var(--pb)}
:root[data-theme="light"] .br-t{background:rgba(15,23,42,.05)}
:root[data-theme="light"] .hb{background:var(--red)}
:root[data-theme="light"] .ct{background:rgba(255,255,255,.5); border-color:var(--pb)}
:root[data-theme="light"] .ct:hover{background:rgba(255,255,255,.8)}
:root[data-theme="light"] .waf-pnl{border-color:rgba(217,119,6,.3)}
:root[data-theme="light"] .waf-row:hover{background:rgba(217,119,6,.1)}
:root[data-theme="light"] .waf-row-ip{color:#b45309}
:root[data-theme="light"] .waf-row-info{color:#334155}
:root[data-theme="light"] .waf-row.new{background:rgba(217,119,6,.15); border-left-color: #b45309;}
:root[data-theme="light"] .ids-pnl{border-color:rgba(126,34,206,.3)}
:root[data-theme="light"] .ids-row:hover{background:rgba(126,34,206,.1)}
:root[data-theme="light"] .ids-row-ip{color:#6b21a8}
:root[data-theme="light"] .ids-row-info{color:#334155}
:root[data-theme="light"] .ids-row.new{background:rgba(126,34,206,.15); border-left-color: #6b21a8;}
:root[data-theme="light"] .atk-tip{background:rgba(255,255,255,.95)!important; border-color:var(--pb)!important; color:var(--tx)!important; box-shadow: var(--panel-shadow)!important;}
:root[data-theme="light"] .msk-tip{background:var(--red)!important; color:#fff!important;}
:root[data-theme="light"] .pr-bd::-webkit-scrollbar-thumb{background:rgba(15,23,42,.2)}
:root[data-theme="light"] .waf-pnl-body::-webkit-scrollbar-thumb{background:rgba(217,119,6,.3)}
:root[data-theme="light"] .ids-pnl-body::-webkit-scrollbar-thumb{background:rgba(126,34,206,.3)}

/* ================== MAP INVERT FOR DARK TOPO ================== */
.leaflet-tile-pane { transition: filter 0.6s ease; }
:root[data-theme="dark"] .leaflet-tile-pane,
:root:not([data-theme="light"]) .leaflet-tile-pane {
    /* ФИКС: Делаем карту светлее и контрастнее, чтобы ландшафт не тонул во тьме */
filter: invert(100%) hue-rotate(180deg) brightness(160%) contrast(90%) saturate(110%);
}
:root[data-theme="light"] .leaflet-tile-pane {
    filter: brightness(85%) contrast(110%);
}


/* ================== GLOBAL ================== */
html,body{width:100%;height:100%;background:var(--bg);color:var(--tx);font-family:var(--fm);overflow:hidden}
#map{position:absolute;top:0;right:0;bottom:0;left:0;z-index:1;background:var(--bg)}
#atkCanvas{position:absolute;top:0;right:0;bottom:0;left:0;z-index:2;pointer-events:none}

.leaflet-control-attribution{background:var(--pn)!important; backdrop-filter: var(--gl-blur); -webkit-backdrop-filter: var(--gl-blur); color:var(--dm)!important;font-family:var(--fm)!important;font-size:9px!important;padding:4px 8px!important;border-radius:6px 0 0 0!important; border-top: 1px solid var(--pb); border-left: 1px solid var(--pb);}
.leaflet-control-attribution a{color:var(--cy)!important}
.leaflet-attribution-flag,.leaflet-control-attribution svg,.leaflet-control-attribution img{display:none!important;width:0!important;height:0!important}
.leaflet-control-zoom{border:1px solid var(--pb)!important;border-radius:6px!important;overflow:hidden; box-shadow: var(--panel-shadow)!important;}
.leaflet-control-zoom a{background:var(--pn)!important; backdrop-filter: var(--gl-blur); -webkit-backdrop-filter: var(--gl-blur); color:var(--tx)!important;border-color:var(--pb)!important;width:32px!important;height:32px!important;line-height:32px!important}
.leaflet-control-zoom a:hover{background:rgba(255,255,255,.1)!important;color:var(--red)!important}

/* ================== HUD ================== */
.hud{position:fixed;top:0;left:0;right:0;z-index:1000;display:flex;align-items:center;justify-content:space-between;padding:0 16px;height:48px;
    background:var(--pn); backdrop-filter: var(--gl-blur); -webkit-backdrop-filter: var(--gl-blur);
    border-bottom:1px solid var(--pb); box-shadow: 0 4px 20px rgba(0,0,0,0.1);}
.hud-l{display:flex;align-items:center;gap:12px}
.hud-l h1{font-family:var(--fd);font-size:12px;font-weight:700;letter-spacing:3px;color:var(--red);text-shadow:0 0 10px var(--rg)}
.live-b{display:flex;align-items:center;gap:6px;padding:3px 8px;background:rgba(255,50,50,.1);border:1px solid rgba(255,50,50,.2);border-radius:12px;font-size:9px;font-weight:bold;color:var(--red);letter-spacing:1px}
.live-d{width:6px;height:6px;background:var(--red);border-radius:50%;animation:bk 1.2s infinite; box-shadow: 0 0 6px var(--red);}
@keyframes bk{0%,100%{opacity:1}50%{opacity:.3}}
.hud-r{display:flex;gap:16px;align-items:center}
.hs{text-align:center;min-width:48px}
.hs-v{font-family:var(--fd);font-size:14px;font-weight:700;line-height:1.1}
.hs-l{font-size:7px;color:var(--dm);text-transform:uppercase;letter-spacing:1.5px;margin-top:2px}

/* ================== REPLAY BAR ================== */
.rbar{position:fixed;top:48px;left:0;right:0;z-index:999;height:36px;
    background:var(--pn); backdrop-filter: var(--gl-blur); -webkit-backdrop-filter: var(--gl-blur);
    border-bottom:1px solid var(--pb);display:flex;align-items:center;padding:0 16px;gap:10px}
.rb{background:transparent;border:1px solid var(--pb);border-radius:4px;padding:3px 10px;color:var(--tx);font-family:var(--fm);font-size:10px;cursor:pointer;display:flex;align-items:center;gap:6px;transition:all .2s;white-space:nowrap}
.rb:hover{border-color:var(--ora);color:var(--ora); background: rgba(255,149,0,0.05);}
.rb.on{background:rgba(255,149,0,.15);border-color:var(--ora);color:var(--ora)}
.rprog{flex:1;height:4px;background:var(--pb);border-radius:2px;overflow:hidden;cursor:pointer}
.rprog-f{height:100%;background:var(--ora);width:0%;transition:width .15s;box-shadow:0 0 8px var(--ora)}
.rinfo{font-size:9px;color:var(--dm);white-space:nowrap;min-width:60px;text-align:right}
.rsp{background:transparent;border:1px solid var(--pb);border-radius:4px;padding:2px 6px;color:var(--dm);font-family:var(--fm);font-size:9px;cursor:pointer}
.rsp:hover{color:var(--yl);border-color:var(--yl)}

/* ================== RIGHT PANEL ================== */
.pr{position:fixed;top:90px;right:10px;bottom:46px;width:320px;z-index:999;
    background:var(--pn); backdrop-filter: var(--gl-blur); -webkit-backdrop-filter: var(--gl-blur);
    border:1px solid var(--pb); border-radius: 8px; box-shadow: var(--panel-shadow);
    display:flex;flex-direction:column;transition:transform .3s cubic-bezier(0.4, 0, 0.2, 1)}
.pr.off{transform:translateX(340px)}
.pr-tg{position:absolute;left:-30px;top:10px;width:30px;height:36px;
    background:var(--pn); backdrop-filter: var(--gl-blur); -webkit-backdrop-filter: var(--gl-blur);
    border:1px solid var(--pb);border-right:none;border-radius:6px 0 0 6px;
    color:var(--tx);font-size:12px;cursor:pointer;display:flex;align-items:center;justify-content:center; box-shadow: -4px 4px 10px rgba(0,0,0,0.1);}
.pr-tabs{display:flex;border-bottom:1px solid var(--pb)}
.pr-tab{flex:1;padding:10px 4px;text-align:center;font-family:var(--fd);font-size:8px;font-weight:600; letter-spacing:1px;color:var(--dm);cursor:pointer;border-bottom:2px solid transparent;transition:all .2s}
.pr-tab:hover{color:var(--tx); background: rgba(255,255,255,0.03);}
.pr-tab.on{color:var(--red);border-bottom-color:var(--red)}
.pr-bd{flex:1;overflow-y:auto;padding:10px}
.pr-bd::-webkit-scrollbar{width:4px}
.pr-bd::-webkit-scrollbar-thumb{background:rgba(150,150,150,.3);border-radius:4px}
.tp{display:none}.tp.on{display:block; animation: fadeIn 0.3s;}
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

/* Log items */
.le{padding:6px 8px;margin-bottom:4px;border-radius:4px;background:rgba(255,50,50,.04);border-left:3px solid var(--rdd);font-size:10px;animation:si .2s ease-out}
.le:hover{background:rgba(255,50,50,.08)}
.le.fr{border-left-color:var(--ora);background:rgba(255,149,0,.05)}
.le.ssh{border-left-color:var(--cy);background:rgba(50,173,230,.05)}
.le.nc{border-left-color:var(--pu);background:rgba(175,82,222,.05)}
@keyframes si{from{opacity:0;transform:translateX(15px)}to{opacity:1;transform:translateX(0)}}
.le-ip{font-weight:700;color:var(--red);font-size:11px}
.le-m{display:flex;justify-content:space-between;margin-top:3px;color:var(--dm);font-size:9px}
.le-c{color:var(--cy)}.le-p{color:var(--yl)}
.le-tag{font-size:7px;padding:2px 5px;border-radius:3px;margin-left:6px;font-weight:700; letter-spacing: 0.5px;}
.le-tag.ipt{background:rgba(255,59,48,.15);color:var(--red)}
.le-tag.ssh{background:rgba(50,173,230,.15);color:var(--cy)}
.le-tag.f2b{background:rgba(255,149,0,.15);color:var(--ora)}
.le-tag.nc{background:rgba(175,82,222,.15);color:var(--pu)}
.le-tag.waf{background:rgba(255,149,0,.2);color:var(--ora)}

/* ================== WAF & IDS PANELS (DRAGGABLE) ================== */
.waf-pnl, .ids-pnl{
    position:fixed; z-index:1000; width:360px; max-height:240px;
    background:var(--pn); backdrop-filter: var(--gl-blur); -webkit-backdrop-filter: var(--gl-blur);
    border-radius:8px; display:flex; flex-direction:column; transition:all .3s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: var(--panel-shadow);
}
.waf-pnl{border:1px solid rgba(255,149,0,.3);}
.ids-pnl{border:1px solid rgba(175,82,222,.3);}

.waf-pnl.collapsed, .ids-pnl.collapsed{max-height:34px; overflow:hidden;}
.waf-pnl-hd, .ids-pnl-hd{
    display:flex; align-items:center; justify-content:space-between; padding:8px 12px; flex-shrink:0;
    cursor:grab; user-select:none; -webkit-user-select:none;
}
.waf-pnl-hd:active, .ids-pnl-hd:active { cursor: grabbing; }

.waf-pnl-hd{border-bottom:1px solid rgba(255,149,0,.15);}
.ids-pnl-hd{border-bottom:1px solid rgba(175,82,222,.15);}

.waf-pnl-hd:hover{background:rgba(255,149,0,.05)}
.ids-pnl-hd:hover{background:rgba(175,82,222,.05)}

.waf-pnl-title{font-family:var(--fd);font-size:10px;font-weight:600;letter-spacing:1px;color:var(--ora);display:flex;align-items:center;gap:6px; pointer-events:none;}
.ids-pnl-title{font-family:var(--fd);font-size:10px;font-weight:600;letter-spacing:1px;color:var(--pu);display:flex;align-items:center;gap:6px; pointer-events:none;}

.waf-pnl-cnt{font-family:var(--fd);font-size:10px;color:var(--ora);font-weight:700;min-width:24px;text-align:center;padding:2px 6px;background:rgba(255,149,0,.15);border-radius:10px}
.ids-pnl-cnt{font-family:var(--fd);font-size:10px;color:var(--pu);font-weight:700;min-width:24px;text-align:center;padding:2px 6px;background:rgba(175,82,222,.15);border-radius:10px}

/* Кнопка сворачивания */
.waf-pnl-tgl, .ids-pnl-tgl{
    font-size:10px;color:var(--dm);transition:transform .3s; padding:4px 8px; cursor:pointer;
    border-radius: 4px; border: 1px solid transparent;
}
.waf-pnl-tgl:hover, .ids-pnl-tgl:hover { background: rgba(255,255,255,0.1); border-color: var(--pb); color: var(--tx); }
.waf-pnl.collapsed .waf-pnl-tgl, .ids-pnl.collapsed .ids-pnl-tgl{transform:rotate(180deg)}

.waf-pnl-body, .ids-pnl-body{flex:1;overflow-y:auto;-webkit-overflow-scrolling:touch;max-height:205px}
.waf-pnl-body::-webkit-scrollbar, .ids-pnl-body::-webkit-scrollbar{width:4px}
.waf-pnl-body::-webkit-scrollbar-thumb{background:rgba(255,149,0,.3);border-radius:4px}
.ids-pnl-body::-webkit-scrollbar-thumb{background:rgba(175,82,222,.3);border-radius:4px}

.waf-row, .ids-row{display:grid; grid-template-columns:100px 1fr 50px; gap:6px; padding:6px 12px; font-size:9.5px; align-items:center; animation: rowIn .3s ease-out;}
.waf-row{border-bottom:1px solid rgba(255,149,0,.08);}
.ids-row{border-bottom:1px solid rgba(175,82,222,.08);}
.waf-row:hover{background:rgba(255,149,0,.08)}
.ids-row:hover{background:rgba(175,82,222,.08)}

@keyframes rowIn{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
.waf-row-ip{color:var(--ora);font-weight:700;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ids-row-ip{color:var(--pu);font-weight:700;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.waf-row-info, .ids-row-info{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--tx)}
.waf-row-info b, .ids-row-info b{color:var(--cy);font-weight:700}
.waf-row-time, .ids-row-time{color:var(--dm);font-size:8.5px;text-align:right}

.waf-row.new{border-left:3px solid var(--ora);background:rgba(255,149,0,.12)}
.ids-row.new{border-left:3px solid var(--pu);background:rgba(175,82,222,.12)}

.waf-empty, .ids-empty{padding:16px;text-align:center;color:var(--dm);font-size:10px}
.le-tag.ids{background:rgba(175,82,222,.25);color:var(--pu)}

/* Charts */
.cb{margin-bottom:12px;background:rgba(0,0,0,.15);border:1px solid var(--pb);border-radius:6px;overflow:hidden}
.cb-t{font-family:var(--fd);font-size:9px;font-weight:600; letter-spacing:1px;color:var(--cy);padding:8px 12px;border-bottom:1px solid var(--pb); background: rgba(0,0,0,0.1);}
.cb-b{padding:10px}
.br{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:10px}
.br-l{width:60px;text-align:right;color:var(--dm);font-weight:600; flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.br-t{flex:1;height:10px;background:var(--pb);border-radius:3px;overflow:hidden}
.br-f{height:100%;border-radius:3px;transition:width .5s}
.br-v{width:45px;font-weight:700;font-family: 'JetBrains Mono', monospace; font-size:9.5px;flex-shrink:0}
.hc{display:flex;align-items:flex-end;gap:2px;height:50px}
.hb{flex:1;background:var(--red);border-radius:2px 2px 0 0;min-width:4px;opacity:.6;transition:all .3s;position:relative}
.hb:hover{opacity:1; background:var(--cy)!important;}
.hb .ht{display:none;position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:var(--pn); backdrop-filter: var(--gl-blur); border:1px solid var(--pb);padding:4px 8px;font-size:9px;white-space:nowrap;border-radius:4px;margin-bottom:4px;z-index:10; box-shadow: var(--panel-shadow);}
.hb:hover .ht{display:block}
/*фикс*/
.hb:last-child .ht {left:auto;right:-5px;transform: none;}
.sr{display:flex;justify-content:space-between;padding:4px 0;font-size:10.5px;border-bottom:1px solid rgba(255,255,255,.05)}
.sr:last-child{border:none}
.sr-l{color:var(--dm); font-weight: 600;}.sr-v{font-weight:700; font-family: 'JetBrains Mono', monospace;}

/* ================== BOTTOM BAR ================== */
.btm{position:fixed;bottom:0;left:0;right:0;z-index:998;padding:6px 16px;
    background:var(--pn); backdrop-filter: var(--gl-blur); -webkit-backdrop-filter: var(--gl-blur);
    border-top:1px solid var(--pb);display:flex;align-items:center;gap:10px;overflow-x:auto; box-shadow: 0 -4px 20px rgba(0,0,0,0.1);}
.btm::-webkit-scrollbar{height:3px}
.btm::-webkit-scrollbar-thumb{background:var(--pb); border-radius:3px;}
.btm-l{font-family:var(--fd);font-size:9px; font-weight: 700; color:var(--dm);letter-spacing:2px;flex-shrink:0; margin-right: 10px;}
.ct{display:flex;align-items:center;gap:6px;padding:4px 10px;background:rgba(15,23,42,.1);border:1px solid var(--pb);border-radius:6px;flex-shrink:0;font-size:10px; transition: all 0.2s;}
.ct:hover{background:rgba(15,23,42,.2); border-color: var(--dm);}
.ct-r{color:var(--dm);font-size:8px; font-weight:700;}.ct-n{color:var(--tx);white-space:nowrap; font-weight: 600;}.ct-c{color:var(--red);font-weight:700;font-family:var(--fd);font-size:11px}.ct-i{color:var(--dm);font-size:8.5px}

/* ================== LEFT PANEL ================== */
.pl{position:fixed;top:94px;left:12px;z-index:999;padding:12px 16px;
    background:var(--pn); backdrop-filter: var(--gl-blur); -webkit-backdrop-filter: var(--gl-blur);
    border:1px solid var(--pb);border-radius:8px;min-width:180px; box-shadow: var(--panel-shadow);}
.pl-t{font-family:var(--fd);font-size:9px;font-weight:700;letter-spacing:2px;color:var(--cy);margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--pb)}
.pl-r{display:flex;justify-content:space-between;padding:3px 0;font-size:10.5px}
.pl-l{color:var(--dm); font-weight: 600;}.pl-v{font-weight:700; font-family: 'JetBrains Mono', monospace;}

/* Mini sparkline */
.spark{display:inline-block;height:18px;vertical-align:middle}
.spark-bar{display:inline-block;width:3px;margin:0 1px;background:var(--cy);border-radius:2px;vertical-align:bottom;opacity:.7}

/* Tooltips */
.atk-tip{
    background:var(--pn)!important; backdrop-filter: var(--gl-blur)!important; border:1px solid var(--pb)!important;
    color:var(--tx)!important;font-family:var(--fm)!important;font-size:11px!important;padding:8px 12px!important;
    border-radius:6px!important; box-shadow: var(--panel-shadow)!important;
    max-width: 250px; white-space: normal !important; word-wrap: break-word;
}
.msk-tip{background:var(--red)!important;border:none!important;color:#fff!important;font-family:var(--fd)!important;font-size:9px!important;font-weight:700;letter-spacing:2px!important;padding:4px 8px!important;border-radius:4px!important; box-shadow: 0 4px 12px rgba(255,59,48,0.5)!important;}

/* Loading */
.lo{position:fixed;top:0;right:0;bottom:0;left:0;z-index:2000;background:var(--bg);display:flex;flex-direction:column;align-items:center;justify-content:center;transition:opacity .5s}
.lo.off{opacity:0;pointer-events:none}
.lo-t{font-family:var(--fd);font-size:16px; font-weight:700; color:var(--red);letter-spacing:6px;margin-bottom:20px;text-shadow:0 0 15px var(--rg)}
.lo-b{width:220px;height:4px;background:var(--pb);border-radius:2px;overflow:hidden}
.lo-f{height:100%;background:var(--red);width:0%;transition:width .3s;box-shadow:0 0 10px var(--rg)}
.lo-s{font-size:11px;color:var(--dm);margin-top:12px; font-weight: 600;}

.scan{position:fixed;top:0;right:0;bottom:0;left:0;z-index:998;pointer-events:none;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.04) 2px,rgba(0,0,0,.04) 4px)}

/* Sound button */
.snd-btn{background:transparent;border:1px solid var(--pb);border-radius:6px;padding:4px 8px;cursor:pointer;font-size:14px;line-height:1;transition:all .2s;opacity:.6}
.snd-btn:hover{opacity:1;border-color:var(--ora); background: rgba(255,255,255,0.05);}
.snd-btn.on{opacity:1;border-color:var(--gn); background: rgba(52,199,89,0.1);}

/* Theme toggle */
.theme-tgl{display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none;-webkit-user-select:none}
.theme-tgl-track{position:relative;width:40px;height:22px;background:rgba(255,255,255,.1);border:1px solid var(--pb);border-radius:11px;transition:all .3s}
.theme-tgl-track:hover{border-color:var(--tx)}
.theme-tgl-knob{position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:var(--yl);transition:all .3s;box-shadow:0 0 8px rgba(255,204,0,.5)}
.theme-tgl-track.light .theme-tgl-knob{left:20px;background:var(--ora);box-shadow:0 0 8px rgba(217,119,6,.5)}
.theme-tgl-ico{font-size:13px;line-height:1;transition:opacity .2s}

/* ── MOBILE ── */
@media(max-width:900px){
    .pr{width:280px}.pr.off{transform:translateX(300px)}
}
@media(max-width:600px){
    .pr{width:260px;top:90px;bottom:40px}.pr.off{transform:translateX(280px)}
    .btm{padding:6px 10px}
    .pl{display:none}
    .waf-pnl{width:calc(100% - 24px);max-height:160px;}
    .waf-pnl.collapsed{max-height:34px}
    .waf-pnl-body{max-height:125px}
    .ids-pnl{width:calc(100% - 24px);max-height:160px;}
    .ids-pnl.collapsed{max-height:34px}
    .ids-pnl-body{max-height:125px}
    .hud-r{gap:8px}.hs-v{font-size:12px}.hs-l{font-size:6.5px}
    .hud-l h1{font-size:10px;letter-spacing:2px}
    .live-b{padding:2px 6px;font-size:8px}
}
</style>
</head>
<body>

<div class="lo" id="loader">
    <div class="lo-t">INITIALIZING V3.2</div>
    <div class="lo-b"><div class="lo-f" id="lBar"></div></div>
    <div class="lo-s" id="lSt">Подключение...</div>
</div>
<div class="scan"></div>
<div id="map"></div>
<canvas id="atkCanvas"></canvas>

<div class="hud">
    <div class="hud-l"><h1>THREAT MAP</h1><div class="live-b"><div class="live-d"></div>LIVE</div><button class="snd-btn" id="sndBtn" onclick="SND.toggle()" title="Звук атак">🔇</button><div class="theme-tgl" onclick="THEME.toggle()" title="Переключить тему"><span class="theme-tgl-ico" id="themeIco">🌙</span><div class="theme-tgl-track" id="themeTrack"><div class="theme-tgl-knob"></div></div></div></div>
    <div class="hud-r">
        <div class="hs"><div class="hs-v" style="color:var(--red)" id="sv-d">—</div><div class="hs-l">Атак сегодня</div></div>
        <div class="hs"><div class="hs-v" style="color:var(--cy)" id="sv-i">—</div><div class="hs-l">Уник. IP</div></div>
        <div class="hs"><div class="hs-v" style="color:var(--ora)" id="sv-b">—</div><div class="hs-l">Забанено</div></div>
        <div class="hs"><div class="hs-v" style="color:var(--pu)" id="sv-ssh">—</div><div class="hs-l">SSH</div></div>
        <div class="hs"><div class="hs-v" style="color:var(--ora)" id="sv-waf">—</div><div class="hs-l">WAF</div></div>
        <div class="hs"><div class="hs-v" style="color:var(--pu)" id="sv-ids">—</div><div class="hs-l">IDS</div></div>
        <div class="hs"><div class="hs-v" style="color:var(--gn)" id="sv-t">—</div><div class="hs-l">CPU</div></div>
        <div class="hs"><div class="hs-v" style="color:var(--yl)" id="sv-load">—</div><div class="hs-l">Load</div></div>
        <div class="hs"><div class="hs-v" style="color:var(--cy)" id="sv-net">—</div><div class="hs-l">Трафик</div></div>
    </div>
</div>

<div class="rbar">
    <button class="rb" id="modeBtn" onclick="MODE.toggle()"><span>📡</span> Реалтайм</button>
<button class="rb" id="rpB" onclick="RP.toggle()"><span>▶</span> Воспроизвести</button>
    <button class="rb" id="rpS" onclick="RP.stop()" style="display:none"><span>⏹</span> Стоп</button>
    <div class="rprog" id="rpP" onclick="RP.seek(event)"><div class="rprog-f" id="rpF"></div></div>
    <div class="rinfo" id="rpI">—</div>
    <button class="rsp" id="rpSp" onclick="RP.speed()">×1</button>
</div>

<div class="pr" id="pr">
    <button class="pr-tg" onclick="PR.tog()">◀</button>
    <div class="pr-tabs">
        <div class="pr-tab on" onclick="PR.tab('log',this)">⚡ АТАКИ</div>
        <div class="pr-tab" onclick="PR.tab('charts',this)">📊 ГРАФИКИ</div>
        <div class="pr-tab" onclick="PR.tab('sys',this)">🖥 СЕРВЕР</div>
        <div class="pr-tab" onclick="PR.tab('info',this)">ℹ ИНФО</div>
    </div>
    <div class="pr-bd">
        <div class="tp on" id="t-log"><div id="logL"></div></div>
        <div class="tp" id="t-charts">
            <div class="cb"><div class="cb-t">АТАКИ ПО ЧАСАМ</div><div class="cb-b"><div class="hc" id="hChart"></div></div></div>
            <div class="cb"><div class="cb-t">ТОП ПОРТОВ</div><div class="cb-b" id="pChart"></div></div>
            <div class="cb"><div class="cb-t">ТОП СТРАН</div><div class="cb-b" id="cChart"></div></div>
            <div class="cb"><div class="cb-t">SSH — ТОП ЛОГИНОВ</div><div class="cb-b" id="sshChart"></div></div>
        </div>
        <div class="tp" id="t-sys">
            <div class="cb"><div class="cb-t">ТРАФИК (1 ЧАС)</div><div class="cb-b" id="trafficChart"></div></div>
            <div class="cb"><div class="cb-t">НАГРУЗКА CPU</div><div class="cb-b" id="loadChart"></div></div>
            <div class="cb"><div class="cb-t">СОЕДИНЕНИЯ</div><div class="cb-b" id="connChart"></div></div>
            <div class="cb"><div class="cb-t">ТЕМПЕРАТУРА</div><div class="cb-b" id="tempChart"></div></div>
            <div class="cb"><div class="cb-t">СЕРВЕР</div><div class="cb-b" id="srvInfo"></div></div>
        </div>
        <div class="tp" id="t-info">
            <div class="cb"><div class="cb-t">СТАТИСТИКА</div><div class="cb-b" id="sInfo"></div></div>
            <div class="cb"><div class="cb-t">О СИСТЕМЕ</div><div class="cb-b">
                <div class="sr"><span class="sr-l">Сервер</span><span class="sr-v" style="color:var(--cy)">Gentoo Linux</span></div>
                <div class="sr"><span class="sr-l">Защита</span><span class="sr-v" style="color:var(--gn)">iptables+f2b+ModSecurity+nginx</span></div>
                <div class="sr"><span class="sr-l">Мониторинг</span><span class="sr-v" style="color:var(--pu)">stats_collector v3</span></div>
                <div class="sr"><span class="sr-l">GeoIP</span><span class="sr-v" style="color:var(--pu)">ip-api + geoiplookup</span></div>
            </div></div>
        </div>
    </div>
</div>

<div class="btm" id="btm"><span class="btm-l">ТОП СТРАН</span></div>

<div class="pl" id="pleft">
    <div class="pl-t">СТАТУС</div>
    <div class="pl-r"><span class="pl-l">Всего атак</span><span class="pl-v" style="color:var(--red)" id="si-t">—</span></div>
    <div class="pl-r"><span class="pl-l">Всего банов</span><span class="pl-v" style="color:var(--ora)" id="si-b">—</span></div>
    <div class="pl-r"><span class="pl-l">Точек</span><span class="pl-v" style="color:var(--cy)" id="si-p">—</span></div>
    <div class="pl-r"><span class="pl-l">Conntrack</span><span class="pl-v" style="color:var(--yl)" id="si-ct">—</span></div>
    <div class="pl-r"><span class="pl-l">RAM</span><span class="pl-v" style="color:var(--gn)" id="si-ram">—</span></div>
</div>

<div class="waf-pnl" id="wafPanel">
    <div class="waf-pnl-hd" title="Удерживайте для перемещения">
        <div class="waf-pnl-title"><span>🛡</span> WAF BLOCKS <span class="waf-pnl-cnt" id="wafCnt">0</span></div>
        <span class="waf-pnl-tgl" onclick="WAF.toggle(); event.stopPropagation();">▼</span>
    </div>
    <div class="waf-pnl-body" id="wafBody"><div class="waf-empty">Ожидание данных...</div></div>
</div>

<div class="ids-pnl" id="idsPanel">
    <div class="ids-pnl-hd" title="Удерживайте для перемещения">
        <div class="ids-pnl-title"><span>🔍</span> SURICATA IDS <span class="ids-pnl-cnt" id="idsCnt">0</span></div>
        <span class="ids-pnl-tgl" onclick="IDS.toggle(); event.stopPropagation();">▼</span>
    </div>
    <div class="ids-pnl-body" id="idsBody"><div class="ids-empty">Ожидание данных...</div></div>
</div>

<script>
window.RT_CFG={
    pollInterval:<?php echo defined('RT_POLL_INTERVAL') ? RT_POLL_INTERVAL : 5000; ?>,
    minDelay:<?php echo defined('RT_MIN_DELAY') ? RT_MIN_DELAY : 200; ?>,
    fetchLimit:<?php echo defined('RT_FETCH_LIMIT') ? RT_FETCH_LIMIT : 50; ?>,
    statsRefresh:<?php echo defined('STATS_REFRESH_INTERVAL') ? STATS_REFRESH_INTERVAL : 30000; ?>,
    chartsRefresh:<?php echo defined('CHARTS_REFRESH_INTERVAL') ? CHARTS_REFRESH_INTERVAL : 120000; ?>
};
window.DEFAULT_THEME='<?php echo defined('DEFAULT_THEME') ? DEFAULT_THEME : 'dark'; ?>';
</script>
<script>
(function(){
'use strict';

const MSK=[55.7558,37.6173],B='<?= ATTACKMAP_BASE_URL ?>';
const CLR=['#dc2626','#ea580c','#d97706','#ca8a04','#0284c7','#7e22ce','#be185d','#16a34a','#ef4444','#f97316'];
let ci=0;function nc(){return CLR[ci++%CLR.length]}

// ==========================================
// 📻 CYBER RADIO: FSK МОДУЛЯТОР (ЗАМЕНА СТАРОГО SND)
// ==========================================
const SND = {
    ctx: null, mode: 0,
    baudRate: 2400,
    queue: Promise.resolve(),

    init() {
        if (this.ctx) return;
        try {
            this.ctx = new (window.AudioContext || window.webkitAudioContext)();
            if (this.ctx.state === 'suspended') this.ctx.resume();
        } catch (e) { console.warn('No audio'); }
    },

    restore() {
        this.mode = 1;
        document.addEventListener('DOMContentLoaded', () => {
            const btn = document.getElementById('sndBtn');
            if (btn) {
                btn.textContent = '🔊';
                btn.title = 'Звук: все';
                btn.classList.add('on');
            }
        });
    },

    toggle() {
        this.init();
        this.mode = (this.mode + 1) % 3;
        const btn = document.getElementById('sndBtn');
        btn.textContent = ['🔇', '🔊', '🔔'][this.mode];
        btn.title = ['Звук: выкл', 'Звук: все', 'Звук: реалтайм'][this.mode];
        btn.classList.toggle('on', this.mode > 0);
        try { localStorage.setItem('atk_snd_mode', this.mode) } catch (e) {}
        if (this.mode === 1) this.transmit('ON', 'IPTables', false);
    },

    textToBits(text) {
        let bits = "";
        for (let i = 0; i < text.length; i++) {
            bits += text.charCodeAt(i).toString(2).padStart(8, '0');
        }
        return bits;
    },

    transmit(text, type = 'IPTables', isBg = false) {
        if (this.mode === 0) return; // Выключено
        if (isBg && this.mode === 2) return; // Только реалтайм
        if (!this.ctx) this.init();
        if (!this.ctx) return;

        // Ставим звук в очередь
        this.queue = this.queue.then(() => new Promise(resolve => {
            const safeText = String(text).substring(0, 16); // Защита от слишком длинных гудков
            const bits = this.textToBits(safeText);
            const bitDuration = 1 / this.baudRate;
            const totalDuration = bits.length * bitDuration;

            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();

            osc.connect(gain);
            gain.connect(this.ctx.destination);

            let f0 = 600, f1 = 1200;
            if (type === 'WAF') { f0 = 1800; f1 = 2800; }
            if (type === 'IDS') { f0 = 200; f1 = 450; }

            const startTime = this.ctx.currentTime;
            const vol = 0.05;

            gain.gain.setValueAtTime(0, startTime);
            gain.gain.linearRampToValueAtTime(vol, startTime + 0.01);
            gain.gain.setValueAtTime(vol, Math.max(startTime + 0.01, startTime + totalDuration - 0.01));
            gain.gain.linearRampToValueAtTime(0, startTime + totalDuration);

            osc.type = 'square';
            osc.frequency.setValueAtTime(bits[0] === '1' ? f1 : f0, startTime);

            for (let i = 1; i < bits.length; i++) {
                const bit = bits[i];
                const time = startTime + (i * bitDuration);
                osc.frequency.setValueAtTime(bit === '1' ? f1 : f0, time);
            }

            osc.start(startTime);
            osc.stop(startTime + totalDuration);

            setTimeout(resolve, totalDuration * 1000 + 10);
        })).catch(() => {});
    },

    beepLive(ip) { this.transmit(ip || 'RT', 'IPTables', false); },
    beepBg(ip) { this.transmit(ip || 'BG', 'IPTables', true); }
};
window.SND = SND;
SND.restore();

const THEME={
    current:'dark',
    tileBase:null,
    init(){
        let saved=null;
        try{saved=localStorage.getItem('atk_theme')}catch(e){}
        const def=window.DEFAULT_THEME||'dark';
        this.current=saved||def;
        this.apply();
    },
    toggle(){
        this.current=this.current==='dark'?'light':'dark';
        try{localStorage.setItem('atk_theme',this.current)}catch(e){}
        this.apply();
    },
    apply(){
        document.documentElement.setAttribute('data-theme',this.current);
        const track=document.getElementById('themeTrack');
        const ico=document.getElementById('themeIco');
        if(track)track.classList.toggle('light',this.current==='light');
        if(ico)ico.textContent=this.current==='dark'?'🌙':'☀️';
        this.switchTiles();
    },
    switchTiles(){
        if(typeof map==='undefined')return;
        if(!this.tileBase){
            this.tileBase=L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}',{
                attribution:'Tiles &copy; Esri',
                maxZoom:12});
            this.tileBase.addTo(map);
        }
    }
};
window.THEME=THEME;
(function(){
    let saved=null;
    try{saved=localStorage.getItem('atk_theme')}catch(e){}
    const def=window.DEFAULT_THEME||'dark';
    const track=document.getElementById('themeTrack');
    const ico=document.getElementById('themeIco');
    const theme=saved||def;
    if(track)track.classList.toggle('light',theme==='light');
    if(ico)ico.textContent=theme==='dark'?'🌙':'☀️';
})();

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function fmt(n){return Number(n||0).toLocaleString('ru-RU')}
async function fj(u){const r=await fetch(u);return r.json()}

const lBar=document.getElementById('lBar'),lSt=document.getElementById('lSt');
function setL(p,t){lBar.style.width=p+'%';lSt.textContent=t}

setL(5,'Карта...');
const map=L.map('map',{center:[35,50],zoom:3,minZoom:2,maxZoom:12,zoomControl:true,preferCanvas:true});
THEME.switchTiles();

requestAnimationFrame(()=>{document.querySelectorAll('.leaflet-attribution-flag').forEach(e=>e.remove());const a=document.querySelector('.leaflet-control-attribution');if(a)a.innerHTML=a.innerHTML.replace(/<svg[^>]*>[\s\S]*?<\/svg>/gi,'').replace(/<img[^>]*>/gi,'')});

document.head.appendChild(Object.assign(document.createElement('style'),{textContent:'@keyframes mP{0%{transform:scale(.5);opacity:1}100%{transform:scale(2.5);opacity:0}}@-webkit-keyframes mP{0%{-webkit-transform:scale(.5);opacity:1}100%{-webkit-transform:scale(2.5);opacity:0}}'}));
L.marker(MSK,{icon:L.divIcon({className:'',html:'<div style="position:relative;width:24px;height:24px"><div style="position:absolute;top:0;right:0;bottom:0;left:0;display:flex;align-items:center;justify-content:center"><div style="width:8px;height:8px;background:var(--red);border-radius:50%;box-shadow:0 0 10px rgba(220,38,38,.8),0 0 25px rgba(220,38,38,.5);z-index:3"></div></div><div style="position:absolute;top:0;right:0;bottom:0;left:0;border:2px solid rgba(220,38,38,.6);border-radius:50%;-webkit-animation:mP 2s ease-out infinite;animation:mP 2s ease-out infinite"></div><div style="position:absolute;top:-4px;right:-4px;bottom:-4px;left:-4px;border:1px solid rgba(220,38,38,.2);border-radius:50%;-webkit-animation:mP 2s ease-out .8s infinite;animation:mP 2s ease-out .8s infinite"></div></div>',iconSize:[24,24],iconAnchor:[12,12]}),zIndexOffset:1000}).addTo(map).bindTooltip('МОСКВА — ЗАЩИТА',{permanent:false,direction:'top',className:'msk-tip',offset:[0,-14]});

setL(15,'Карта ОК');

const cvs=document.getElementById('atkCanvas');
const ctx=cvs.getContext('2d');
let arcs=[],imps=[];

function resizeCvs(){cvs.width=window.innerWidth;cvs.height=window.innerHeight}
window.addEventListener('resize',resizeCvs);resizeCvs();

function ll2px(ll){
    const p=map.latLngToContainerPoint(L.latLng(ll[0],ll[1]));
    return [p.x,p.y];
}

function fireAtk(fromLL,color){
    arcs.push({from:fromLL,t:0,c:color||'#dc2626',sp:.004+Math.random()*.005,tr:.12+Math.random()*.08});
    if(arcs.length>300)arcs.splice(0,100);
}

function tickCanvas(){
    ctx.clearRect(0,0,cvs.width,cvs.height);
    const msk=ll2px(MSK);

    for(let i=arcs.length-1;i>=0;i--){
        const a=arcs[i];a.t+=a.sp;
        if(a.t>=1){imps.push({px:msk,c:a.c,t:0});arcs.splice(i,1);continue}

        const fp=ll2px(a.from),tp=msk;
        const dx=tp[0]-fp[0],dy=tp[1]-fp[1],d=Math.sqrt(dx*dx+dy*dy);
        if(d<2)continue;
        const arc=-d*.28,mx=(fp[0]+tp[0])/2,my=(fp[1]+tp[1])/2+arc;
        const t=a.t,t0=Math.max(0,t-a.tr);

        const hx=(1-t)*(1-t)*fp[0]+2*(1-t)*t*mx+t*t*tp[0];
        const hy=(1-t)*(1-t)*fp[1]+2*(1-t)*t*my+t*t*tp[1];
        const tx2=(1-t0)*(1-t0)*fp[0]+2*(1-t0)*t0*mx+t0*t0*tp[0];
        const ty2=(1-t0)*(1-t0)*fp[1]+2*(1-t0)*t0*my+t0*t0*tp[1];

        const g=ctx.createLinearGradient(tx2,ty2,hx,hy);
        g.addColorStop(0,'transparent');g.addColorStop(.5,a.c+'66');g.addColorStop(1,a.c+'ff');

        ctx.beginPath();
        for(let s=0;s<=12;s++){
            const st=t0+(t-t0)*(s/12);
            const sx=(1-st)*(1-st)*fp[0]+2*(1-st)*st*mx+st*st*tp[0];
            const sy=(1-st)*(1-st)*fp[1]+2*(1-st)*st*my+st*st*tp[1];
            s===0?ctx.moveTo(sx,sy):ctx.lineTo(sx,sy);
        }
        ctx.strokeStyle=g;ctx.lineWidth=2.5;ctx.stroke();

        ctx.beginPath();ctx.arc(hx,hy,3.5,0,Math.PI*2);
        ctx.fillStyle=a.c;ctx.shadowColor=a.c;ctx.shadowBlur=12;ctx.fill();ctx.shadowBlur=0;
    }

    for(let i=imps.length-1;i>=0;i--){
        const im=imps[i];im.t+=.035;
        if(im.t>=1){imps.splice(i,1);continue}
        const r=5+im.t*30,al=1-im.t;
        const hex=Math.round(al*200).toString(16).padStart(2,'0');
        const rg=ctx.createRadialGradient(im.px[0],im.px[1],0,im.px[0],im.px[1],r);
        rg.addColorStop(0,im.c+hex);rg.addColorStop(1,'transparent');
        ctx.beginPath();ctx.arc(im.px[0],im.px[1],r,0,Math.PI*2);ctx.fillStyle=rg;ctx.fill();
    }

    requestAnimationFrame(tickCanvas);
}
tickCanvas();

const mG=L.layerGroup().addTo(map),pM={};
function addPt(lat,lon,ip,country,attacks,ports){
    if(pM[ip])return;const c=nc(),sz=Math.min(4+Math.log2(attacks||1)*1.5,12);
    const m=L.circleMarker([lat,lon],{radius:sz,color:c,fillColor:c,fillOpacity:.4,weight:1.5,opacity:.7}).addTo(mG);

    let pStr = '';
    if(ports){
        const pArr = String(ports).split(',');
        if(pArr.length > 15) {
            pStr = pArr.slice(0, 15).join(', ') + ' <span style="color:var(--ora)">... (еще ' + (pArr.length - 15) + ')</span>';
        } else {
            pStr = pArr.join(', ');
        }
        pStr = '<div style="margin-top:6px; font-size:8.5px; color:var(--dm); line-height:1.4;"><b>Порты:</b> ' + pStr + '</div>';
    }

    m.bindTooltip('<b style="color:'+c+';font-size:12px;">'+esc(ip)+'</b><br><span style="color:var(--tx)">'+esc(country||'??')+'</span> · <b style="color:var(--red)">'+(attacks||1)+'</b> атак' + pStr, {className:'atk-tip',direction:'top'});
    pM[ip]=m;
}

const logL=document.getElementById('logL');
let logC=0;
function addLog(a,fr,type){
    const el=document.createElement('div');
    const cls=type==='ssh'?' ssh':type==='nc'?' nc':type==='waf'?' fr':(fr?' fr':'');
    el.className='le'+cls;
    const tm=a.time?new Date(a.time.replace(' ','T')).toLocaleTimeString('ru-RU'):'';
    const tag=type?'<span class="le-tag '+(type||'ipt')+'">'+esc(type||'IPT').toUpperCase()+'</span>':'';
    const detail=a.user?'<span class="le-p">@'+esc(a.user)+'</span>':'<span class="le-p">:'+esc(a.port||'—')+'</span>';
    el.innerHTML='<div class="le-ip">'+esc(a.ip)+tag+'</div><div class="le-m"><span class="le-c">'+esc(a.country||'??')+'</span>'+detail+'<span>'+tm+'</span></div>';
    logL.insertBefore(el,logL.firstChild);logC++;
    while(logL.children.length>300)logL.removeChild(logL.lastChild);
}

const PR={
    tog(){const p=document.getElementById('pr');p.classList.toggle('off');p.querySelector('.pr-tg').textContent=p.classList.contains('off')?'▶':'◀'},
    tab(id,el){document.querySelectorAll('.pr-tab').forEach(t=>t.classList.remove('on'));document.querySelectorAll('.tp').forEach(t=>t.classList.remove('on'));el.classList.add('on');document.getElementById('t-'+id).classList.add('on');
        if(id==='sys')loadMetrics();
    }
};window.PR=PR;

function makeBarChart(container, items, labelKey, valueKey, colors){
    const el=document.getElementById(container);if(!el)return;el.innerHTML='';
    if(!items||!items.length)return;
    const cl=colors||CLR;
    const mx=Math.max(...items.map(p=>+p[valueKey]||0),1);
    items.forEach((p,i)=>{const pc=(+p[valueKey]/mx)*100;
        el.innerHTML+='<div class="br"><span class="br-l" title="'+esc(p[labelKey])+'">'+esc(String(p[labelKey]).substring(0,8))+'</span><div class="br-t"><div class="br-f" style="width:'+pc+'%;background:'+cl[i%cl.length]+'"></div></div><span class="br-v" style="color:'+cl[i%cl.length]+'">'+fmt(p[valueKey])+'</span></div>'});
}

function makeSparkline(data, key, color){
    if(!data||!data.length)return '';
    const vals=data.map(d=>+d[key]||0);
    const mx=Math.max(...vals,0.01);
    let html='<div class="spark">';
    const step=Math.max(1,Math.floor(vals.length/20));
    for(let i=0;i<vals.length;i+=step){
        const h=Math.max(2,Math.round(vals[i]/mx*16));
        html+='<span class="spark-bar" style="height:'+h+'px;background:'+(color||'var(--cy)')+'"></span>';
    }
    return html+'</div>';
}

let lastTime=null;

function animateCount(el,target){
    const cur=parseInt(el.textContent.replace(/\s/g,''))||0;
    if(cur>=target)return;
    const diff=target-cur;
    const steps=Math.min(diff,30);
    const perStep=Math.max(1,Math.floor(diff/steps));
    let v=cur,step=0;
    function tick(){
        v+=perStep;if(v>=target)v=target;
        el.textContent=fmt(v);
        step++;
        if(v<target&&step<steps)setTimeout(tick,50);
    }
    tick();
}

async function loadStats(){
    try{
        const s=await fj(B+'?stats=1');
        animateCount(document.getElementById('sv-d'),s.today_drops);
        animateCount(document.getElementById('sv-i'),s.today_ips);
        animateCount(document.getElementById('sv-b'),s.today_bans);
        document.getElementById('sv-t').textContent=s.cpu_temp?Math.round(s.cpu_temp)+'°':'—';
        document.getElementById('sv-ssh').textContent=fmt(s.today_ssh||0);
        document.getElementById('sv-waf').textContent=fmt(s.today_waf||0);
        document.getElementById('sv-ids').textContent=fmt(s.today_ids||0);
        document.getElementById('sv-load').textContent=s.load_1m?s.load_1m.toFixed(1):'—';
        const rx=s.rx_mbps||0,tx=s.tx_mbps||0;
        document.getElementById('sv-net').textContent=(rx+tx)<1?Math.round((rx+tx)*1024)+'K':(rx+tx).toFixed(1)+'M';

        document.getElementById('si-t').textContent=fmt(s.total_drops);
        document.getElementById('si-b').textContent=fmt(s.total_bans);
        document.getElementById('si-ct').textContent=fmt(s.conntrack||0);
        if(s.ram_used_mb&&s.ram_total_mb){
            document.getElementById('si-ram').textContent=Math.round(s.ram_used_mb)+'/'+ Math.round(s.ram_total_mb)+'M';
        }
        document.getElementById('sInfo').innerHTML=
            sr('Сегодня',fmt(s.today_drops),'--red')+sr('Вчера',fmt(s.yesterday_drops),'--red')+
            sr('Неделя',fmt(s.week_drops),'--ora')+sr('Всего',fmt(s.total_drops),'--ora')+
            sr('IP сегодня',fmt(s.today_ips),'--cy')+sr('Банов сегодня',fmt(s.today_bans),'--pu')+
            sr('Банов всего',fmt(s.total_bans),'--pu')+sr('Nginx блок',fmt(s.nginx_blocks),'--yl')+
            sr('SSH атак',fmt(s.today_ssh||0),'--cy')+sr('NC auth',fmt(s.today_nc_auth||0),'--pu')+
            sr('WAF блок',fmt(s.today_waf||0),'--ora')+
            sr('IDS алерт',fmt(s.today_ids||0),'--pu')+
            sr('CPU',s.cpu_temp?Math.round(s.cpu_temp)+'°C':'—','--gn')+
            sr('Load',s.load_1m?s.load_1m.toFixed(2):'—','--yl')+
            sr('Conntrack',fmt(s.conntrack||0),'--cy')+
            sr('GeoIP',fmt(s.geo_cached),'--cy');
    }catch(e){console.error(e)}
}
function sr(l,v,c){return'<div class="sr"><span class="sr-l">'+l+'</span><span class="sr-v" style="color:var('+c+')">'+v+'</span></div>'}

async function loadHourly(){
    try{
        const d=await fj(B+'?hourly=1'),hrs=d.hourly||[];
        const ch=document.getElementById('hChart');ch.innerHTML='';
        const hm={};hrs.forEach(h=>{if(h.hkey)hm[h.hkey]=+h.cnt});
        const mx=Math.max(...Object.values(hm),1);
        const now=new Date();
        for(let off=23;off>=0;off--){
            const d2=new Date(now.getTime()-off*3600000);
            const y=d2.getFullYear(),mo=String(d2.getMonth()+1).padStart(2,'0'),da=String(d2.getDate()).padStart(2,'0'),hh=String(d2.getHours()).padStart(2,'0');
            const key=y+'-'+mo+'-'+da+' '+hh;
            const v=hm[key]||0;
            const p=Math.max(2,(v/mx)*100);
            const b=document.createElement('div');b.className='hb';b.style.height=p+'%';
            if(off===0)b.style.background='var(--ora)';
            b.innerHTML='<div class="ht">'+d2.getHours()+':00 — '+fmt(v)+'</div>';
            ch.appendChild(b);
        }
    }catch(e){console.error(e)}
}

async function loadPorts(){
    try{
        const d=await fj(B+'?ports=1'),pts=d.ports||[];
        makeBarChart('pChart', pts.map(p=>({label:':'+p.port, cnt:p.cnt})), 'label', 'cnt');
    }catch(e){console.error(e)}
}

async function loadCountries(){
    try{
        const d=await fj(B+'?countries=1'),c=d.countries||[];
        const bar=document.getElementById('btm');bar.innerHTML='<span class="btm-l">ТОП СТРАН</span>';
        c.forEach((x,i)=>{bar.innerHTML+='<div class="ct"><span class="ct-r">#'+(i+1)+'</span><span class="ct-n">'+esc(x.country)+'</span><span class="ct-c">'+fmt(x.cnt)+'</span><span class="ct-i">'+x.ips+'IP</span></div>'});
        makeBarChart('cChart', c.slice(0,10).map(x=>({label:x.country.substring(0,10), cnt:x.cnt})), 'label', 'cnt');
    }catch(e){console.error(e)}
}

async function loadSSH(){
    try{
        const d=await fj(B+'?ssh=1');
        makeBarChart('sshChart', (d.top_users||[]).slice(0,10), 'username', 'cnt',
            ['var(--cy)','#0284c7','#0369a1','#075985','#0c4a6e','var(--gn)','#16a34a','#15803d','#166534','#14532d']);
    }catch(e){console.error(e)}
}

async function loadMetrics(){
    try{
        const d=await fj(B+'?metrics=1');
        const tc=document.getElementById('trafficChart');
        if(d.traffic&&d.traffic.length){
            tc.innerHTML=sr('↓ Входящий',makeSparkline(d.traffic,'rx','var(--gn)'),'--gn')+
                sr('↑ Исходящий',makeSparkline(d.traffic,'tx','var(--ora)'),'--ora');
        } else tc.innerHTML='<div class="sr"><span class="sr-l">Нет данных</span></div>';

        const lc=document.getElementById('loadChart');
        if(d.load&&d.load.length){
            lc.innerHTML=sr('Load 1m',makeSparkline(d.load,'l1','var(--yl)'),'--yl')+
                sr('RAM MB',makeSparkline(d.load,'ram','var(--pu)'),'--pu');
        } else lc.innerHTML='<div class="sr"><span class="sr-l">Нет данных</span></div>';

        const cc=document.getElementById('connChart');
        if(d.conntrack&&d.conntrack.length){
            cc.innerHTML=sr('Соединения',makeSparkline(d.conntrack,'c','var(--cy)'),'--cy');
        } else cc.innerHTML='<div class="sr"><span class="sr-l">Нет данных</span></div>';

        const tc2=document.getElementById('tempChart');
        if(d.temp&&d.temp.length){
            tc2.innerHTML=sr('°C',makeSparkline(d.temp,'temp','var(--red)'),'--red');
        } else tc2.innerHTML='<div class="sr"><span class="sr-l">Нет данных</span></div>';

        document.getElementById('srvInfo').innerHTML=
            sr('Интерфейс',NET_IF,'--cy')+sr('Интервал','60 сек','--dm')+sr('Хранение','3 мес','--dm');
    }catch(e){console.error(e)}
}

async function loadAllGeo(){
    setL(25,'Гео-данные...');
    try{
        const d=await fj(B+'?all_geo=1'),pts=d.points||[];
        setL(45,pts.length+' точек...');
        document.getElementById('si-p').textContent=fmt(pts.length);
        let idx=0;
        return new Promise(res=>{(function go(){const end=Math.min(idx+60,pts.length);
            for(;idx<end;idx++){const p=pts[idx];if(p.lat&&p.lon)addPt(+p.lat,+p.lon,p.ip,p.country,+p.attacks,p.ports)}
            setL(Math.round(45+(idx/pts.length)*30),'Точки: '+idx+'/'+pts.length);
            idx<pts.length?requestAnimationFrame(go):res(pts)})()})
    }catch(e){console.error(e);return[]}
}

const RTQ={
    queue:[], timer:null, processing:false,
    enqueue(attacks, isRealtime){
        attacks.forEach(a => this.queue.push({attack:a, rt:isRealtime}));
        if(!this.processing) this.process();
    },
    process(){
        if(this.queue.length===0){this.processing=false;return}
        this.processing=true;
        const batch=[...this.queue];
        this.queue=[];
        const count=batch.length;
        const cfg=window.RT_CFG||{pollInterval:5000,minDelay:200};
        const maxDelay=cfg.pollInterval-500;
        const idealDelay=count>1?Math.floor(maxDelay/count):0;
        const delay=Math.max(cfg.minDelay, idealDelay);

        let idx=0;
        const showNext=()=>{
            if(idx>=batch.length){this.processing=false;return}
            const item=batch[idx];
            const x=item.attack;

            addLog(x,item.rt,'ipt');
            if(x.lat&&x.lon){
                const c=nc();
                addPt(+x.lat,+x.lon,x.ip,x.country||'??',1,x.port);
                if(item.rt){
                    fireAtk([+x.lat,+x.lon],c);
                    // Передаем в звук реальный IP!
                    SND.beepLive(x.ip);
                }
            }
            idx++;
            if(idx<batch.length){
                this.timer=setTimeout(showNext, delay);
            } else {
                this.processing=false;
            }
        };
        showNext();
    },
    clear(){
        clearTimeout(this.timer);
        this.queue=[];
        this.processing=false;
    }
};

async function pollAttacks(){
    try{
        const cfg=window.RT_CFG||{fetchLimit:50};
        let u=B+'?attacks=1&limit='+cfg.fetchLimit;if(lastTime)u+='&since='+encodeURIComponent(lastTime);
        const d=await fj(u),a=d.attacks||[];
        const cutoff=new Date(Date.now()+86400000);
        const cutStr=cutoff.getFullYear()+'-'+String(cutoff.getMonth()+1).padStart(2,'0')+'-'+String(cutoff.getDate()).padStart(2,'0');
        const valid=a.filter(x=>!x.time||x.time.slice(0,10)<=cutStr);

        const isRealtime = !!lastTime;
        const ts=valid.map(x=>x.time).filter(t=>t&&t.slice(0,10)<=cutStr);
        if(ts.length)lastTime=ts.reduce((a,b)=>a>b?a:b);

        if(valid.length>0){
            RTQ.enqueue(valid, isRealtime);
        }
    }catch(e){console.error(e)}
}

const RP={
    data:null,playing:false,idx:0,timer:null,speeds:[1,2,5,10,20,50],si:0,
    async toggle(){
        if(this.playing){this.pause();return}
        if(!this.data){
            document.getElementById('rpI').textContent='Загрузка кеша...';
            try{const d=await fj(B+'?replay_cache=1');this.data=d.attacks||[];
            document.getElementById('rpI').textContent='Кеш: '+this.data.length+' атак'}
            catch(e){document.getElementById('rpI').textContent='Ошибка!';return}
        }
        this.playing=true;this.idx=0;
        document.getElementById('rpB').classList.add('on');
        document.getElementById('rpB').innerHTML='<span>⏸</span> Пауза';
        document.getElementById('rpS').style.display='flex';
        this.next();
    },
    pause(){this.playing=false;clearTimeout(this.timer);
        document.getElementById('rpB').innerHTML='<span>▶</span> Далее';
        document.getElementById('rpB').classList.add('on')},
    stop(){this.playing=false;clearTimeout(this.timer);this.idx=0;
        document.getElementById('rpB').innerHTML='<span>▶</span> Воспроизвести';
        document.getElementById('rpB').classList.remove('on');
        document.getElementById('rpS').style.display='none';
        document.getElementById('rpF').style.width='0%';
        document.getElementById('rpI').textContent='—'},
    next(){
        if(!this.playing||!this.data)return;
        if(this.idx>=this.data.length){this.stop();return}
        const a=this.data[this.idx];
        if(a.lat&&a.lon){
            fireAtk([+a.lat,+a.lon],nc());
            addPt(+a.lat,+a.lon,a.ip,a.country||'??',1,a.port);
            SND.beepBg(a.ip);
        }
        addLog(a,true);
        this.idx++;
        document.getElementById('rpF').style.width=(this.idx/this.data.length*100)+'%';
        document.getElementById('rpI').textContent=this.idx+'/'+this.data.length;
        this.timer=setTimeout(()=>this.next(),Math.max(15,120/this.speeds[this.si]));
    },
    speed(){this.si=(this.si+1)%this.speeds.length;document.getElementById('rpSp').textContent='×'+this.speeds[this.si]},
    seek(e){if(!this.data)return+'%';
        if(this.playing){clearTimeout(this.timer);this.next()}}
};window.RP=RP;

const BG={
    pts:null,idx:0,timer:null,active:false,
    start(points){
        this.pts=[...points].sort(()=>Math.random()-.5);
        this.idx=0;
        if(this.active)this.tick();
    },
    tick(){
        if(!this.active||!this.pts||this.pts.length===0)return;
        const count=1+Math.floor(Math.random()*2);
        for(let i=0;i<count;i++){
            const p=this.pts[this.idx%this.pts.length];
            if(p.lat&&p.lon){
                fireAtk([+p.lat,+p.lon],nc());
                SND.beepBg(p.ip);
            }
            this.idx++;
        }
        const delay=400+Math.random()*600;
        this.timer=setTimeout(()=>this.tick(),delay);
    },
    stop(){this.active=false;clearTimeout(this.timer)},
    resume(){this.active=true;if(this.pts)this.tick()}
};

const MODE={
    current:'rt',
    toggle(){
        if(this.current==='bg'){
            this.current='rt';
            BG.stop();
            document.getElementById('modeBtn').innerHTML='<span>📡</span> Реалтайм';
            document.getElementById('modeBtn').classList.remove('on');
        } else {
            this.current='bg';
            BG.resume();
            document.getElementById('modeBtn').innerHTML='<span>🌐</span> Фон';
            document.getElementById('modeBtn').classList.add('on');
        }
    }
};
window.MODE=MODE;

const DRAG = {
    init(panelId, defaultTop) {
        const panel = document.getElementById(panelId);
        if(!panel) return;
        const header = panel.querySelector('.waf-pnl-hd') || panel.querySelector('.ids-pnl-hd');
        if(!header) return;

        let isDragging = false;
        let startX, startY, initialX, initialY;

        try {
            const pos = JSON.parse(localStorage.getItem('atk_pos_' + panelId));
            if(pos && pos.l !== undefined && pos.t !== undefined) {
                panel.style.left = pos.l + 'px';
                panel.style.top = pos.t + 'px';
            } else {
                panel.style.top = defaultTop + 'px';
                panel.style.left = '12px';
            }
        } catch(e){
            panel.style.top = defaultTop + 'px';
            panel.style.left = '12px';
        }

        const onDown = (e) => {
            if(e.target.tagName === 'SPAN' || e.target.closest('span')) return;
            isDragging = true;
            const evt = e.touches ? e.touches[0] : e;
            startX = evt.clientX;
            startY = evt.clientY;

            const rect = panel.getBoundingClientRect();
            initialX = rect.left;
            initialY = rect.top;

            panel.style.transition = 'none';

            document.addEventListener(e.touches ? 'touchmove' : 'mousemove', onMove, {passive: false});
            document.addEventListener(e.touches ? 'touchend' : 'mouseup', onUp);
        };

        const onMove = (e) => {
            if(!isDragging) return;
            e.preventDefault();
            const evt = e.touches ? e.touches[0] : e;
            const dx = evt.clientX - startX;
            const dy = evt.clientY - startY;

            let newX = initialX + dx;
            let newY = initialY + dy;

            newX = Math.max(0, Math.min(newX, window.innerWidth - panel.offsetWidth));
            newY = Math.max(0, Math.min(newY, window.innerHeight - panel.offsetHeight));

            panel.style.left = newX + 'px';
            panel.style.top = newY + 'px';
        };

        const onUp = () => {
            if(!isDragging) return;
            isDragging = false;
            panel.style.transition = 'all .3s cubic-bezier(0.4, 0, 0.2, 1)';

            try {
                localStorage.setItem('atk_pos_' + panelId, JSON.stringify({
                    l: parseInt(panel.style.left),
                    t: parseInt(panel.style.top)
                }));
            } catch(e){}

            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
            document.removeEventListener('touchmove', onMove);
            document.removeEventListener('touchend', onUp);
        };

        header.addEventListener('mousedown', onDown);
        header.addEventListener('touchstart', onDown, {passive: false});
    }
};

const WAF={
    panel:null, body:null, cntEl:null, maxRows:30, collapsed:false,
    init(){
        this.panel=document.getElementById('wafPanel');
        this.body=document.getElementById('wafBody');
        this.cntEl=document.getElementById('wafCnt');
    },
    toggle(){
        if(!this.panel)return;
        this.collapsed=!this.collapsed;
        this.panel.classList.toggle('collapsed',this.collapsed);
    },
    addRow(w,isNew){
        if(!this.body)return;
        const empty=this.body.querySelector('.waf-empty');
        if(empty)empty.remove();

        const el=document.createElement('div');
        el.className='waf-row'+(isNew?' new':'');
        const tm=w.time?new Date(w.time.replace(' ','T')).toLocaleTimeString('ru-RU'):'';
        const uriShort=(w.uri||'/').substring(0,40);
        const ruleShort=(w.rule_msg||'').substring(0,35);
        el.innerHTML=
            '<span class="waf-row-ip" title="'+esc(w.ip)+'">'+esc(w.ip)+'</span>'+
            '<span class="waf-row-info" title="'+esc(w.uri||'')+'"><b>'+esc(w.method||'GET')+'</b> '+esc(uriShort)+' <span style="color:var(--dm)">'+esc(ruleShort)+'</span></span>'+
            '<span class="waf-row-time">'+tm+'</span>';
        this.body.insertBefore(el,this.body.firstChild);

        if(isNew) this.body.scrollTop=0;
        if(isNew) setTimeout(()=>{el.classList.remove('new')},8000);

        while(this.body.children.length>this.maxRows){
            this.body.removeChild(this.body.lastChild);
        }

        if(isNew&&w.lat&&w.lon){
            addPt(+w.lat,+w.lon,w.ip,w.country||'??',1,'WAF');
            fireAtk([+w.lat,+w.lon],'#d97706');
            // Передаем звук как WAF
            SND.transmit(w.ip, 'WAF', false);
        }

        if(isNew){
            addLog({ip:w.ip,country:w.country||'??',port:'WAF:'+w.rule_id,time:w.time},true,'waf');
        }
    },
    updateCount(n){
        if(this.cntEl)this.cntEl.textContent=n;
    }
};
window.WAF=WAF;

let wafLastTime=null;
async function pollWAF(){
    try{
        let u=B+'?waf=1&limit=20';
        if(wafLastTime)u+='&since='+encodeURIComponent(wafLastTime);
        const d=await fj(u);
        const attacks=d.attacks||[];

        if(d.today!==undefined){
            WAF.updateCount(d.today);
            const el=document.getElementById('sv-waf');
            if(el)animateCount(el,d.today);
        }

        const isRealtime=!!wafLastTime;
        if(attacks.length>0){
            const ts=attacks.map(x=>x.time).filter(Boolean);
            if(ts.length)wafLastTime=ts.reduce((a,b)=>a>b?a:b);
            const toShow=isRealtime?attacks:attacks.slice(0,10).reverse();
            toShow.forEach(w=>WAF.addRow(w,isRealtime));
        }
    }catch(e){console.error('WAF poll:',e)}
}

const IDS={
    panel:null, body:null, cntEl:null, maxRows:30, collapsed:false,
    init(){
        this.panel=document.getElementById('idsPanel');
        this.body=document.getElementById('idsBody');
        this.cntEl=document.getElementById('idsCnt');
    },
    toggle(){
        if(!this.panel)return;
        this.collapsed=!this.collapsed;
        this.panel.classList.toggle('collapsed',this.collapsed);
    },
    addRow(a,isNew){
        if(!this.body)return;
        const empty=this.body.querySelector('.ids-empty');
        if(empty)empty.remove();

        const el=document.createElement('div');
        el.className='ids-row'+(isNew?' new':'');
        const tm=a.time?new Date(a.time.replace(' ','T')).toLocaleTimeString('ru-RU'):'';
        const sigShort=(a.sig_msg||'').replace(/^ET\s+/,'').substring(0,40);
        const sevColors={1:'var(--red)',2:'var(--ora)',3:'var(--dm)'};
        const sevColor=sevColors[a.severity]||'var(--dm)';
        el.innerHTML=
            '<span class="ids-row-ip" title="'+esc(a.ip)+'">'+esc(a.ip)+'</span>'+
            '<span class="ids-row-info" title="'+esc(a.sig_msg||'')+'"><b style="color:'+sevColor+'">'+esc(a.proto||'TCP')+'</b> :'+esc(a.port||'—')+' <span style="color:var(--dm)">'+esc(sigShort)+'</span></span>'+
            '<span class="ids-row-time">'+tm+'</span>';
        this.body.insertBefore(el,this.body.firstChild);

        if(isNew) this.body.scrollTop=0;
        if(isNew) setTimeout(()=>{el.classList.remove('new')},8000);

        while(this.body.children.length>this.maxRows){
            this.body.removeChild(this.body.lastChild);
        }

        if(isNew&&a.lat&&a.lon){
            addPt(+a.lat,+a.lon,a.ip,a.country||'??',1,'IDS:'+a.sig_id);
            fireAtk([+a.lat,+a.lon],'#7e22ce');
            // Передаем звук как IDS
            SND.transmit(a.ip, 'IDS', false);
        }

        if(isNew){
            addLog({ip:a.ip,country:a.country||'??',port:'IDS:'+a.port,time:a.time},true,'ids');
        }
    },
    updateCount(n){
        if(this.cntEl)this.cntEl.textContent=n;
    }
};
window.IDS=IDS;

let idsLastTime=null;
async function pollIDS(){
    try{
        let u=B+'?ids=1&limit=20';
        if(idsLastTime)u+='&since='+encodeURIComponent(idsLastTime);
        const d=await fj(u);
        const attacks=d.attacks||[];

        if(d.today!==undefined){
            IDS.updateCount(d.today);
            const el=document.getElementById('sv-ids');
            if(el)animateCount(el,d.today);
        }

        const isRealtime=!!idsLastTime;
        if(attacks.length>0){
            const ts=attacks.map(x=>x.time).filter(Boolean);
            if(ts.length)idsLastTime=ts.reduce((a,b)=>a>b?a:b);
            const toShow=isRealtime?attacks:attacks.slice(0,10).reverse();
            toShow.forEach(a=>IDS.addRow(a,isRealtime));
        }
    }catch(e){console.error('IDS poll:',e)}
}

(async function(){
    await loadStats();setL(20,'Статистика...');
    const pts=await loadAllGeo();setL(78,'Графики...');
    await Promise.all([loadCountries(),loadHourly(),loadPorts(),loadSSH()]);
    setL(85,'Атаки...');

    WAF.init();
    IDS.init();

    const wh = window.innerHeight;
    DRAG.init('idsPanel', wh > 800 ? wh - 600 : 250);
    DRAG.init('wafPanel', wh > 800 ? wh - 330 : 500);

    await pollAttacks();await pollWAF();await pollIDS();
    setL(92,'Запуск потока...');
    if(pts.length>0)BG.start(pts);
    setL(100,'Готово!');setTimeout(()=>document.getElementById('loader').classList.add('off'),500);
    const cfg=window.RT_CFG||{pollInterval:5000,statsRefresh:30000,chartsRefresh:120000};
    setInterval(pollAttacks,cfg.pollInterval);setInterval(pollWAF,cfg.pollInterval);setInterval(pollIDS,cfg.pollInterval);setInterval(loadStats,cfg.statsRefresh);setInterval(()=>{loadCountries();loadHourly();loadPorts();loadSSH()},cfg.chartsRefresh);
})();

// Разрешаем звук по первому клику на любом месте документа
document.body.addEventListener('click', () => { SND.init(); }, {once: true});

})();
</script>
</body>
</html>
