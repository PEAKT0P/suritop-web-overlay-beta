<?php
/**
 * iptables-manager PHP API bridge
 * Подключается к Python-демону через Unix-сокет
 * и предоставляет JSON API для веб-интерфейса.
 *
 * Размещается в защищённой директории nginx (basic_auth)
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-cache, no-store, must-revalidate');

// ─── Конфигурация ───
define('SOCKET_PATH', '/tmp/iptables-manager.sock');
define('MAX_REQUEST_SIZE', 4096);
define('SOCKET_TIMEOUT', 10);

// ─── CSRF-токен (простой, т.к. за basic_auth) ───
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ─── Функции ───

function send_to_daemon($request) {
    if (!file_exists(SOCKET_PATH)) {
        return ['error' => 'Daemon not running (socket not found)'];
    }

    $socket = @stream_socket_client('unix://' . SOCKET_PATH, $errno, $errstr, SOCKET_TIMEOUT);
    if (!$socket) {
        return ['error' => "Cannot connect to daemon: $errstr ($errno)"];
    }

    stream_set_timeout($socket, SOCKET_TIMEOUT);

    $json = json_encode($request, JSON_UNESCAPED_UNICODE) . "\n";
    fwrite($socket, $json);

    $response = '';
    while (!feof($socket)) {
        $chunk = fread($socket, 65536);
        if ($chunk === false || $chunk === '') break;
        $response .= $chunk;
        // Ответ заканчивается \n
        if (substr($response, -1) === "\n") break;
    }
    fclose($socket);

    $data = json_decode(trim($response), true);
    if ($data === null) {
        return ['error' => 'Invalid response from daemon', 'raw' => substr($response, 0, 500)];
    }

    return $data;
}

function validate_ip($ip) {
    return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
}

function validate_port($port) {
    $port = (int) $port;
    return $port >= 1 && $port <= 65535;
}

function validate_proto($proto) {
    return in_array($proto, ['tcp', 'udp'], true);
}

// ─── Роутинг ───

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? 'full_report';

// Для POST-действий (модификация правил) проверяем CSRF
if ($method === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input) {
        echo json_encode(['error' => 'Invalid POST body']);
        exit;
    }

    $action = $input['action'] ?? '';
    $params = $input['params'] ?? [];

    // Валидация csrf
    $csrf = $input['csrf'] ?? '';
    if ($csrf !== $_SESSION['csrf_token']) {
        http_response_code(403);
        echo json_encode(['error' => 'Invalid CSRF token']);
        exit;
    }

    // Валидация параметров
    $write_actions = ['block_ip', 'unblock_ip', 'open_port', 'close_port'];
    if (in_array($action, $write_actions)) {
        if (in_array($action, ['block_ip', 'unblock_ip'])) {
            if (!isset($params['ip']) || !validate_ip($params['ip'])) {
                echo json_encode(['error' => 'Invalid IP address']);
                exit;
            }
        }
        if (in_array($action, ['open_port', 'close_port'])) {
            if (!isset($params['port']) || !validate_port($params['port'])) {
                echo json_encode(['error' => 'Invalid port number']);
                exit;
            }
            if (isset($params['proto']) && !validate_proto($params['proto'])) {
                echo json_encode(['error' => 'Invalid protocol']);
                exit;
            }
        }
    }

    $response = send_to_daemon([
        'action' => $action,
        'params' => $params,
    ]);

    echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// GET-запросы (только чтение)
$read_actions = [
    'full_report', 'list_rules', 'list_ports', 'list_docker',
    'list_fail2ban', 'system_info', 'list_nat', 'list_forward',
    'list_connections', 'csrf_token',
];

if ($action === 'csrf_token') {
    echo json_encode(['token' => $_SESSION['csrf_token']]);
    exit;
}

if (!in_array($action, $read_actions)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid action for GET request']);
    exit;
}

$response = send_to_daemon([
    'action' => $action,
    'params' => [],
]);

echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);