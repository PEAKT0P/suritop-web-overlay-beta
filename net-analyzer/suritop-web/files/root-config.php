<?php
$conf_file = "/etc/suritop-web/collector.conf";
$defaults = [
    "host" => "localhost", "name" => "server_stats",
    "user_r" => "stats_reader", "pass_r" => "",
    "user_w" => "stats_writer", "pass_w" => ""
];
$db = $defaults;
if (file_exists($conf_file)) {
    $section = "";
    $ini = [];
    foreach (file($conf_file) as $line) {
        $line = trim($line);
        if ($line === "" || $line[0] === "#" || $line[0] === ";") continue;
        if (preg_match('/^\[(.+)\]$/', $line, $m)) { $section = $m[1]; continue; }
        if (preg_match('/^(\w+)\s*=\s*(.+)$/', $line, $m)) { $ini[$section][$m[1]] = trim($m[2]); }
    }
    if (isset($ini["Database"])) $db = array_merge($db, $ini["Database"]);
    if (isset($ini["Network"]["our_ip"])) define("OUR_IP", $ini["Network"]["our_ip"]);
}
define("STATS_DB_HOST", $db["host"]);
define("STATS_DB_NAME", $db["name"]);
define("STATS_DB_USER", $db["user_r"]);
define("STATS_DB_PASS", $db["pass_r"]);
define("CACHE_FILE", "/tmp/attack_replay_cache.json");
define("CACHE_TTL", 300);
define("RT_POLL_INTERVAL", 5000);
define("RT_MIN_DELAY", 200);
define("RT_FETCH_LIMIT", 50);
define("STATS_REFRESH_INTERVAL", 30000);
define("CHARTS_REFRESH_INTERVAL", 120000);
define("DEFAULT_THEME", "dark");
define("ATTACKMAP_BASE_URL", "/suritop/attackmap/");
define("WAF_BASE_URL", "/suritop/admin_stats.php");
