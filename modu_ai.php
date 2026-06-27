<?php
header('Content-Type: application/json; charset=utf-8');
// ===== 全局初始化 =====
$request_id = bin2hex(random_bytes(8));
$request_start_time = microtime(true);

// ===== 环境变量兼容函数（适配宝塔PHP-FPM） =====
function env($k, $d = '') {
    $v = $_SERVER[$k] ?? $_ENV[$k] ?? getenv($k) ?: false;
    return $v === false || (is_string($v) && trim($v) === '') ? $d : trim($v);
}

// ===== 核心配置 =====
// 跨域白名单，可改成自己网站
$allow_origins = ['https://oak360.cn', 'https://www.oak360.cn'];
// 可信代理IP段（CDN/反向代理，只有来自这些IP的请求头才可信）
$trusted_proxies = []; 
// 模型熔断配置：连续失败N次后熔断M秒
$circuit_breaker_fail_count = 5;
$circuit_breaker_break_seconds = 600;
// 模型配置
$deepseek_url = 'https://api.deepseek.com/chat/completions';
$deepseek_model = 'deepseek-v4-flash';
$deepseek_key = env('DEEPSEEK_KEY');
$zhipu_url = 'https://open.bigmodel.cn/api/paas/v4/chat/completions';   
$zhipu_model = 'glm-4-flash';
$zhipu_key = env('ZHIPU_KEY');
// 额度配置
$daily_limit_free = 50;
$daily_limit_vip = 200;
$max_devices_per_token = 3;
// 限流配置
$rate_per_second = 2;
$rate_per_minute = 60;
$rate_per_hour = 500;
$max_text_length = 2000;
// 解释功能配置
$explain_max_len = 80;
$explain_prompt_version = 'v1';
$explain_cache_ttl = 30 * 86400; // 缓存30天过期
// 数据目录（与程序文件同级）
$data_dir = __DIR__ . '/modu_data';
$log_dir = __DIR__ . '/modu_log';
$limit_file = $data_dir . '/ai_call_limit.json';
$rate_minute_file = $data_dir . '/rate_minute.json';
$rate_hour_file = $data_dir . '/rate_hour.json';
$stats_file = $data_dir . '/stats.json';
$token_file = $data_dir . '/vip_tokens.json';
$black_ip_file = $data_dir . '/black_ip.json';
$rate_limit_file = $data_dir . '/second_rate_limit.json';
$explain_cache_file = $data_dir . '/explain_cache.json';
$circuit_breaker_file = $data_dir . '/circuit_breaker.json';
$error_log_file = $log_dir . '/error_' . date('Y-m-d') . '.log';
$access_log_file = $log_dir . '/access_' . date('Y-m-d') . '.log';
// 初始化目录与文件
foreach ([$data_dir, $log_dir] as $dir) {
    if (!is_dir($dir)) mkdir($dir, 0700, true);
}
foreach ([$limit_file, $rate_minute_file, $rate_hour_file, $stats_file, $token_file, $black_ip_file, $rate_limit_file, $explain_cache_file, $circuit_breaker_file] as $f) {
    if (!file_exists($f)) {
        touch($f);
        chmod($f, 0600);
        file_put_contents($f, json_encode([], JSON_UNESCAPED_UNICODE));
    }
}
// 目录访问防护
@file_put_contents("$data_dir/index.html", '');
@file_put_contents("$data_dir/.htaccess", "deny from all\n");
@file_put_contents("$log_dir/index.html", '');
@file_put_contents("$log_dir/.htaccess", "deny from all\n");

// ===== 跨域安全（标准化） =====
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allow_origins, true)) {
    header("Access-Control-Allow-Origin: $origin");
    header('Vary: Origin');
}
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Vip-Token, X-Device-ID');
header('Access-Control-Max-Age: 86400');
// 安全响应头
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
// 预检请求
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ===== 基础工具函数 =====
function lockAndRead($file) {
    $fp = fopen($file, 'c+');
    if (!$fp) return [null, null];
    flock($fp, LOCK_EX);
    rewind($fp);
    $raw = stream_get_contents($fp);
    $data = json_decode($raw, true) ?: [];
    return [$fp, $data];
}
function writeAndUnlock($fp, $data) {
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_UNESCAPED_UNICODE));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
}
function writeErrorLog($msg) {
    global $error_log_file, $request_id;
    $line = '[' . date('Y-m-d H:i:s') . '] [req:' . $request_id . '] ' . $msg . PHP_EOL;
    file_put_contents($error_log_file, $line, FILE_APPEND);
}
function writeAccessLog($data) {
    global $access_log_file;
    $line = json_encode($data, JSON_UNESCAPED_UNICODE) . PHP_EOL;
    // 日志轮转：20M自动备份
    if (file_exists($access_log_file) && filesize($access_log_file) > 20 * 1024 * 1024) {
        $backup = $access_log_file . '.' . date('YmdHis');
        rename($access_log_file, $backup);
    }
    file_put_contents($access_log_file, $line, FILE_APPEND);
}
// 获取真实IP：仅信任配置的代理IP，防止X-Forwarded-For伪造
function getRealIp() {
    global $trusted_proxies;
    $remote_addr = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    
    // REMOTE_ADDR不在可信代理列表，直接返回，不读取任何转发头
    if (empty($trusted_proxies) || !in_array($remote_addr, $trusted_proxies)) {
        return filter_var($remote_addr, FILTER_VALIDATE_IP) ? $remote_addr : '127.0.0.1';
    }
    
    // 可信代理下，优先读取CF真实IP，其次X-Forwarded-For第一个IP
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ips[0]);
        if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
    }
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = trim($_SERVER['HTTP_X_REAL_IP']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
    }
    
    return $remote_addr;
}
// 设备指纹（仅作辅助，不作为核心身份依据）
function getDeviceFingerprint() {
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $lang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'unknown';
    return sha1($ua . '|' . $lang);
}
function getDeviceId() {
    if (isset($_COOKIE['modu_device_id']) && preg_match('/^[a-f0-9]{32}$/', $_COOKIE['modu_device_id'])) {
        return $_COOKIE['modu_device_id'];
    }
    $device_id = md5(uniqid(mt_rand(), true) . getDeviceFingerprint());
    setcookie('modu_device_id', $device_id, time() + 31536000, '/', '',
        isset($_SERVER['HTTPS']), true, ['samesite' => 'Lax']);
    return $device_id;
}
// 文本标准化：修复全角转半角Bug，支持变形绕过检测
function normalizeText($text) {
    $text = mb_strtolower($text);
    // 全角字符转半角（修复ord()单字节问题）
    $text = preg_replace_callback('/[\x{FF01}-\x{FF5E}]/u', function($m) {
        $code = mb_ord($m[0], 'UTF-8');
        return mb_chr($code - 0xFEE0, 'UTF-8');
    }, $text);
    // 移除所有空白、标点、特殊符号、分隔符
    $text = preg_replace('/[\s\p{P}\p{Z}\p{S}_\-·・]/u', '', $text);
    return $text;
}
// 违规内容检测
function isIllegalText($text) {
    $badWords = [
        '色情','黄片','裸聊','嫖娼','约炮','博彩','网赌','赌博',
        '毒品','冰毒','白粉','吸毒','贩毒',
        '杀人','自杀教程','暴力伤人','虐猫','虐狗',
        '诈骗','刷单','杀猪盘','盗号','破解密码',
        '翻墙','梯子','vpn','科学上网','越狱工具'
    ];
    $clean = normalizeText($text);
    foreach ($badWords as $w) {
        if (mb_strpos($clean, $w) !== false) return true;
    }
    return false;
}
// AI精读返回结果校验
function validateAiResponse($data) {
    if (!is_array($data)) return false;
    // 锚点校验：去重、长度限制
    if (!isset($data['anchors']) || !is_array($data['anchors']) || count($data['anchors']) < 2) return false;
    if (count(array_unique($data['anchors'])) !== count($data['anchors'])) return false;
    foreach ($data['anchors'] as $a) {
        if (!is_string($a) || trim($a) === '' || mb_strlen($a) > 12) return false;
    }
    // 题干校验
    if (!isset($data['question']) || !is_string($data['question']) || mb_strlen($data['question']) > 80) return false;
    // 选项校验：4个、去重、长度限制
    if (!isset($data['options']) || !is_array($data['options']) || count($data['options']) !== 4) return false;
    if (count(array_unique($data['options'])) !== count($data['options'])) return false;
    foreach ($data['options'] as $opt) {
        if (!is_string($opt) || mb_strlen($opt) > 40) return false;
    }
    // 正确答案校验
    if (!isset($data['correctIndex']) || !is_int($data['correctIndex']) || $data['correctIndex'] < 0 || $data['correctIndex'] > 3) return false;
    // 反馈校验
    if (!isset($data['feedback']) || !is_string($data['feedback']) || mb_strlen($data['feedback']) > 60) return false;
    if (!isset($data['wrongFeedback']) || !is_string($data['wrongFeedback']) || mb_strlen($data['wrongFeedback']) > 60) return false;
    return true;
}
// 限流：仅清理过期数据，保留有效记录（修复时间戳判断bug）
function checkRateLimit($file, $key, $max, $ttl = 60) {
    list($fp, $data) = lockAndRead($file);
    // 拿不到锁直接拒绝，不能放行
    if (!$fp) return false;
    
    $now = time();
    // 清理TTL外的过期记录
    foreach ($data as $k => $v) {
        $parts = explode('|', $k, 2);
        if (count($parts) < 2) {
            unset($data[$k]);
            continue;
        }
        $ts = isset($parts[0]) ? (int)$parts[0] : 0;
        if ($ts <= 0 || ($now - $ts) > $ttl) {
            unset($data[$k]);
        }
    }
    
    if (!isset($data[$key])) $data[$key] = 0;
    if ($data[$key] >= $max) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return false;
    }
    $data[$key]++;
    writeAndUnlock($fp, $data);
    return true;
}
// ===== 熔断器 =====
function checkCircuitBreaker($model_name) {
    global $circuit_breaker_file, $circuit_breaker_fail_count, $circuit_breaker_break_seconds;
    list($fp, $data) = lockAndRead($circuit_breaker_file);
    if (!$fp) return false;
    
    $now = time();
    if (!isset($data[$model_name])) {
        $data[$model_name] = ['fail_count' => 0, 'break_until' => 0];
    }
    $breaker = &$data[$model_name];
    
    // 熔断中
    if ($breaker['break_until'] > $now) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return true;
    }
    // 熔断到期，重置计数
    if ($breaker['break_until'] > 0 && $breaker['break_until'] <= $now) {
        $breaker['fail_count'] = 0;
        $breaker['break_until'] = 0;
    }
    writeAndUnlock($fp, $data);
    return false;
}
function recordModelResult($model_name, $success) {
    global $circuit_breaker_file, $circuit_breaker_fail_count, $circuit_breaker_break_seconds;
    list($fp, $data) = lockAndRead($circuit_breaker_file);
    if (!$fp) return;
    
    $now = time();
    if (!isset($data[$model_name])) {
        $data[$model_name] = ['fail_count' => 0, 'break_until' => 0];
    }
    
    if ($success) {
        $data[$model_name]['fail_count'] = 0;
        $data[$model_name]['break_until'] = 0;
    } else {
        $data[$model_name]['fail_count']++;
        if ($data[$model_name]['fail_count'] >= $circuit_breaker_fail_count) {
            $data[$model_name]['break_until'] = $now + $circuit_breaker_break_seconds;
            writeErrorLog("模型熔断 模型:{$model_name} 连续失败{$circuit_breaker_fail_count}次，熔断{$circuit_breaker_break_seconds}秒");
        }
    }
    writeAndUnlock($fp, $data);
}
// 统一模型调用：支持重试、熔断、耗时统计
function callLLM($url, $api_key, $model_name, $model_code, $system_prompt, $user_text, $json_mode = false, $temperature = 0.3, $retry = 1) {
    if (empty($api_key)) return [null, 0, 0];
    
    // 熔断检查
    if (checkCircuitBreaker($model_name)) {
        return [null, 0, 0];
    }
    
    $post_data = [
        'model' => $model_code,
        'temperature' => $temperature,
        'messages' => [
            ['role' => 'system', 'content' => $system_prompt],
            ['role' => 'user', 'content' => $user_text]
        ]
    ];
    if ($json_mode) {
        $post_data['response_format'] = ['type' => 'json_object'];
    }
    
    $last_http_code = 0;
    $last_error = '';
    $total_cost = 0;
    $success = false;
    $final_content = null;
    
    for ($i = 0; $i <= $retry; $i++) {
        $start = microtime(true);
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($post_data),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $api_key
            ],
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2
        ]);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);
        $cost_ms = round((microtime(true) - $start) * 1000);
        $total_cost += $cost_ms;
        $last_http_code = $http_code;
        $last_error = $curl_error;
        
        if (!$curl_error && $http_code === 200 && $response) {
            $result = json_decode($response, true);
            if (isset($result['error'])) {
                $last_error = is_array($result['error']) ? ($result['error']['message'] ?? '未知错误') : $result['error'];
                continue;
            }
            $content = $result['choices'][0]['message']['content'] ?? '';
            if ($content) {
                $final_content = $content;
                $success = true;
                break;
            }
        }
        if ($i < $retry) usleep(300000);
    }
    
    // 记录熔断状态
    recordModelResult($model_name, $success);
    if (!$success) {
        writeErrorLog("模型调用失败 模型:{$model_name} HTTP:{$last_http_code} 错误:{$last_error} 重试:{$retry}次");
    }
    
    return [$final_content, $last_http_code, $total_cost];
}
// 额度回滚
function rollbackQuota($key, $today) {
    global $limit_file;
    list($fp, $data) = lockAndRead($limit_file);
    if ($fp && isset($data[$key]) && $data[$key]['date'] === $today && $data[$key]['count'] > 0) {
        $data[$key]['count']--;
        writeAndUnlock($fp, $data);
    } elseif ($fp) {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}
// ===== 运行时基础信息 =====
$ip = getRealIp();
$device_id = getDeviceId();
$device_fp = getDeviceFingerprint();
$now = time();
$today = date('Y-m-d');
$minute_key = date('Y-m-d H:i');
$hour_key = date('Y-m-d H');
$device_log_id = substr(sha1($device_id), 0, 6); // 脱敏设备标识
// IP黑名单
$black_ips = json_decode(file_get_contents($black_ip_file), true) ?: [];
if (in_array($ip, $black_ips)) {
    echo json_encode(['code' => 403, 'msg' => '访问受限', 'request_id' => $request_id]);
    exit;
}
// 三级限流
if (!checkRateLimit($rate_limit_file, (string)$now . '|' . $device_id, $rate_per_second, 1)) {
    echo json_encode(['code' => 429, 'msg' => '请求过于频繁，请稍后再试', 'request_id' => $request_id]);
    exit;
}
if (!checkRateLimit($rate_minute_file, $minute_key . '|' . $device_id, $rate_per_minute, 60)) {
    echo json_encode(['code' => 429, 'msg' => '请求过于频繁，请稍后再试', 'request_id' => $request_id]);
    exit;
}
if (!checkRateLimit($rate_hour_file, $hour_key . '|' . $device_id, $rate_per_hour, 3600)) {
    echo json_encode(['code' => 429, 'msg' => '调用过于频繁，请稍后再试', 'request_id' => $request_id]);
    exit;
}
// ===== VIP校验 + 设备绑定 =====
$clientToken = $_SERVER['HTTP_X_VIP_TOKEN'] ?? '';
$is_vip = false;
$vip_expire = 0;
$vip_days = 0;
if (!empty($clientToken) && ctype_xdigit($clientToken)) {
    list($fp, $tokenData) = lockAndRead($token_file);
    if ($fp && isset($tokenData[$clientToken])) {
        $tk = &$tokenData[$clientToken];
        if ($tk['expire'] > $now) {
            if (!isset($tk['devices']) || !is_array($tk['devices'])) {
                $tk['devices'] = [];
            }
            if (!in_array($device_fp, $tk['devices'])) {
                if (count($tk['devices']) < $max_devices_per_token) {
                    $tk['devices'][] = $device_fp;
                    $is_vip = true;
                }
            } else {
                $is_vip = true;
            }
            if ($is_vip) {
                $vip_expire = $tk['expire'];
                $vip_days = ceil(($tk['expire'] - $now) / 86400);
            }
        } else {
            unset($tokenData[$clientToken]);
        }
        writeAndUnlock($fp, $tokenData);
    } elseif ($fp) {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}
// 会员状态查询
if (isset($_GET['action']) && $_GET['action'] === 'check') {
    echo json_encode([
        'vip' => $is_vip,
        'expire' => $vip_expire,
        'days' => $vip_days,
        'max_devices' => $max_devices_per_token,
        'request_id' => $request_id
    ]);
    exit;
}
// ===== 每日额度校验 =====
$current_limit = $is_vip ? $daily_limit_vip : $daily_limit_free;
list($fp, $limit_data) = lockAndRead($limit_file);
if (!$fp) {
    writeErrorLog('限流文件读取失败');
    echo json_encode(['code' => 500, 'msg' => '服务异常', 'request_id' => $request_id]);
    exit;
}
// 清理过期数据
foreach ($limit_data as $key => $item) {
    if ($item['date'] !== $today) unset($limit_data[$key]);
}
// 1. 设备维度额度校验（原有逻辑）
$limit_key = $device_id;
if (!isset($limit_data[$limit_key])) {
    $limit_data[$limit_key] = ['date' => $today, 'count' => 0];
}
if ($limit_data[$limit_key]['count'] >= $current_limit) {
    flock($fp, LOCK_UN);
    fclose($fp);
    $tip = $is_vip ? '今日AI调用已达上限' : '今日免费次数已用完，请开通会员';
    echo json_encode(['code' => 429, 'msg' => $tip, 'request_id' => $request_id]);
    exit;
}
$limit_data[$limit_key]['count']++;
// 2. IP维度兜底校验（仅对免费用户生效，防止清Cookie刷量）
if (!$is_vip) {
    $ip_limit_key = 'ip_' . $ip;
    $ip_daily_max = 200; // 单IP每日免费调用上限，可自行调整
    if (!isset($limit_data[$ip_limit_key])) {
        $limit_data[$ip_limit_key] = ['date' => $today, 'count' => 0];
    }
    if ($limit_data[$ip_limit_key]['count'] >= $ip_daily_max) {
        flock($fp, LOCK_UN);
        fclose($fp);
        echo json_encode(['code' => 429, 'msg' => '今日免费次数已用完，请开通会员', 'request_id' => $request_id]);
        exit;
    }
    $limit_data[$ip_limit_key]['count']++;
}

writeAndUnlock($fp, $limit_data);
// ===== 文本校验与清洗 =====
$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true);
$text = trim($input['text'] ?? '');
$text = preg_replace('/[\x00-\x1F\x7F\xA0]/u', '', $text);
if (isIllegalText($text)) {
    rollbackQuota($limit_key, $today);
    echo json_encode(['code' => 403, 'msg' => '文本包含违规内容', 'request_id' => $request_id]);
    exit;
}
// 深度清洗，保证Prompt稳定
$text = strip_tags($text);
$text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
$text = preg_replace('/\s+/u', ' ', $text);
$text = trim($text);
$text_len = mb_strlen($text);
if ($text_len < 2) {
    rollbackQuota($limit_key, $today);
    echo json_encode(['code' => 400, 'msg' => '选中内容过短', 'request_id' => $request_id]);
    exit;
}
if ($text_len > $max_text_length) {
    rollbackQuota($limit_key, $today);
    echo json_encode(['code' => 400, 'msg' => "文本过长，请分段阅读（单段不超过{$max_text_length}字）", 'request_id' => $request_id]);
    exit;
}
// ===== 划词极简解释接口 =====
$action = isset($input['action']) ? trim($input['action']) : 'full';
if ($action === 'explain') {
    if ($text_len > $explain_max_len) {
        rollbackQuota($limit_key, $today);
        echo json_encode(['code' => 400, 'msg' => '请选择更小范围的内容进行解释', 'request_id' => $request_id]);
        exit;
    }
    // 模型列表，按优先级排序
    $model_list = [];
    if ($is_vip && !empty($deepseek_key)) {
        $model_list[] = ['name' => 'deepseek', 'url' => $deepseek_url, 'key' => $deepseek_key, 'code' => $deepseek_model];
    }
    if (!empty($zhipu_key)) {
        $model_list[] = ['name' => 'zhipu', 'url' => $zhipu_url, 'key' => $zhipu_key, 'code' => $zhipu_model];
    }
    if (empty($model_list)) {
        rollbackQuota($limit_key, $today);
        echo json_encode(['code' => 500, 'msg' => 'AI服务暂不可用', 'request_id' => $request_id]);
        exit;
    }
    $primary_model = $model_list[0]['name'];
    $cache_key = md5($explain_prompt_version . '|' . $primary_model . '|' . $text);
    $is_cached = false;
    $used_model = $primary_model;
    $ai_cost_ms = 0;
    // 读取缓存，带TTL过期清理
    list($cache_fp, $cache_data) = lockAndRead($explain_cache_file);
    if ($cache_fp && isset($cache_data[$cache_key])) {
        $item = $cache_data[$cache_key];
        // 检查是否过期
        if (is_array($item) && isset($item['time']) && ($now - $item['time']) < $explain_cache_ttl) {
            $is_cached = true;
            $result_text = $item['content'];
        } else {
            // 过期删除
            unset($cache_data[$cache_key]);
        }
    }
    // 清理所有过期缓存
    if ($cache_fp) {
        foreach ($cache_data as $k => $v) {
            if (!is_array($v) || !isset($v['time']) || ($now - $v['time']) >= $explain_cache_ttl) {
                unset($cache_data[$k]);
            }
        }
    }
    if ($is_cached && $cache_fp) {
        flock($cache_fp, LOCK_UN);
        fclose($cache_fp);
    }
    // 无缓存调用AI
    if (!$is_cached) {
        $explain_prompt = <<<EOF
你是阅读场景下的极简词典，唯一目标是帮助用户继续阅读。
用户会给你「待解释词语」和「所在段落上下文」。
严格遵守以下规则：
1. 必须结合本段上下文的语境解释，不要通用字面含义
2. 只解释选中文字本身的含义，不分析作者观点、不总结段落、不扩展背景、不举例
3. 人名地名专有名词直接说明身份/类别
4. 不用书面语，尽量通俗直白
5. 输出必须≤18个汉字，超出请自行压缩精简
6. 禁止使用Markdown、编号、引号、Emoji、任何格式符号
7. 直接输出解释内容，不要任何前缀后缀
EOF;
        $ai_result = null;
        foreach ($model_list as $m) {
            list($ai_result, $http_code, $cost_ms) = callLLM(
                $m['url'], $m['key'], $m['name'], $m['code'],
                $explain_prompt, $text,
                false, 0.3, 1
            );
            $ai_cost_ms += $cost_ms;
            if ($ai_result) {
                $used_model = $m['name'];
                break;
            }
        }
        if (!$ai_result) {
            if ($cache_fp) { flock($cache_fp, LOCK_UN); fclose($cache_fp); }
            rollbackQuota($limit_key, $today);
            echo json_encode(['code' => 500, 'msg' => 'AI服务暂不可用', 'request_id' => $request_id]);
            exit;
        }
        // 清洗结果
        $result_text = trim($ai_result);
        $result_text = preg_replace('/[#*`"\'_\-\r\n\t]/', '', $result_text);
        $result_text = preg_replace('/\s+/', ' ', $result_text);
        if (mb_strlen($result_text) > 22) {
            $result_text = mb_substr($result_text, 0, 20) . '…';
        }
        // 写入缓存
        if ($cache_fp) {
            if (count($cache_data) > 1000) {
                $cache_data = array_slice($cache_data, -500, null, true);
            }
            $cache_data[$cache_key] = [
                'content' => $result_text,
                'time' => $now
            ];
            writeAndUnlock($cache_fp, $cache_data);
        }
    }
    // 更新统计
    list($fp, $stats) = lockAndRead($stats_file);
    if ($fp) {
        foreach ($stats as $date => $item) {
            $timestamp = strtotime($date);
            if ($timestamp < $now - 30 * 86400) unset($stats[$date]);
        }
        if (!isset($stats[$today])) {
            $stats[$today] = [
                'ai_calls' => 0, 'explain_calls' => 0, 'cache_hits' => 0,
                'ai_ip_count' => 0, 'new_vips' => 0, 'active_ip_count' => 0,
                'ai_ips' => [], 'active_ips' => []
            ];
        }
        $stats[$today]['ai_calls']++;
        $stats[$today]['explain_calls']++;
        if ($is_cached) $stats[$today]['cache_hits']++;
        if (!isset($stats[$today]['ai_ips'][$ip])) {
            $stats[$today]['ai_ips'][$ip] = 1;
            $stats[$today]['ai_ip_count']++;
        }
        if (!isset($stats[$today]['active_ips'][$ip])) {
            $stats[$today]['active_ips'][$ip] = 1;
            $stats[$today]['active_ip_count']++;
        }
        writeAndUnlock($fp, $stats);
    }
    // 访问日志（设备ID脱敏）
    writeAccessLog([
        'request_id' => $request_id,
        'time' => date('Y-m-d H:i:s'),
        'device_hash' => $device_log_id,
        'ip_mask' => substr($ip, 0, (int)strrpos($ip, '.') + 2) . '*',
        'is_vip' => $is_vip,
        'action' => 'explain',
        'cached' => $is_cached,
        'model_used' => $used_model,
        'text_len' => $text_len,
        'ai_cost_ms' => $ai_cost_ms,
        'total_cost_ms' => round((microtime(true) - $request_start_time) * 1000)
    ]);
    echo json_encode([
        'code' => 0,
        'request_id' => $request_id,
        'cached' => $is_cached,
        'data' => $result_text,
        'model' => $used_model
    ]);
    exit;
}
// ===== 精读模式系统提示词 =====
$system_prompt = <<<EOF
你是专为ADHD人群设计的阅读辅助引擎，仅处理正规文学、书籍、科普、学术类合规文本。
请对用户输入的单段文本，严格按要求输出结果，不要任何多余解释。
如果用户输入违规内容，直接返回{"err":"内容不符合阅读规范"}。
任务要求：
1. 提取2-4个语义核心锚点
   - 必须是这段文字中最关键的名词、名词短语、专有名词、核心概念
   - 禁止提取虚词、连接词、通用形容词、单字词
   - 所有锚点必须在原文中完整出现，不得自行编造
   - 短文本2个即可，长文本不超过4个，宁少勿滥
2. 生成1道四选一的理解测试题
   - 题目只考察原文直接表达的核心事实/观点，不考推断、不抠细节
   - 正确选项必须是原文明确给出的信息，不得过度引申
   - 3个干扰项要符合常识，但与本段核心内容不符
   - 题干和选项都要简短，减少阅读负担
   - correctIndex为正确选项序号，从0开始，必须是整数
3. 生成反馈语
   - 答对反馈：温和正向，肯定用户的理解
   - 答错反馈：温和引导重读，不能出现负面词汇
输出要求：
严格输出纯JSON格式，不要markdown、不要代码块、不要任何前言。
字段严格如下：
{
  "anchors": ["词1", "词2"],
  "question": "题目题干",
  "options": ["A. 选项内容", "B. 选项内容", "C. 选项内容", "D. 选项内容"],
  "correctIndex": 0,
  "feedback": "答对的正向反馈",
  "wrongFeedback": "答错的引导语"
}
EOF;
// ===== 双轨调用逻辑 =====
$ai_data = null;
$used_model = 'zhipu';
$ai_cost_ms = 0;
$mode = isset($input['mode']) ? trim($input['mode']) : 'standard';
$model_list = [];
if ($is_vip && $mode === 'ai' && !empty($deepseek_key)) {
    $model_list[] = ['name' => 'deepseek', 'url' => $deepseek_url, 'key' => $deepseek_key, 'code' => $deepseek_model];
}
if (!empty($zhipu_key)) {
    $model_list[] = ['name' => 'zhipu', 'url' => $zhipu_url, 'key' => $zhipu_key, 'code' => $zhipu_model];
}
foreach ($model_list as $m) {
    $json_mode = (strpos($m['code'], 'deepseek') !== false);
    list($content, $http_code, $cost_ms) = callLLM(
        $m['url'], $m['key'], $m['name'], $m['code'],
        $system_prompt, $text,
        $json_mode, 0.3, 1
    );
    $ai_cost_ms += $cost_ms;
    if (!$content) continue;
    
    $first = strpos($content, '{');
    $last = strrpos($content, '}');
    if ($first !== false && $last !== false) {
        $content = substr($content, $first, $last - $first + 1);
    }
    $parsed = json_decode($content, true);
    if (validateAiResponse($parsed)) {
        $ai_data = $parsed;
        $used_model = $m['name'];
        break;
    } else {
        writeErrorLog("精读返回格式校验失败 模型:{$m['name']}");
        recordModelResult($m['name'], false);
    }
}
if (!$ai_data) {
    rollbackQuota($limit_key, $today);
    echo json_encode(['code' => 500, 'msg' => 'AI服务暂不可用，请稍后重试', 'request_id' => $request_id]);
    exit;
}
// ===== 更新统计 =====
list($fp, $stats) = lockAndRead($stats_file);
if ($fp) {
    foreach ($stats as $date => $item) {
        $timestamp = strtotime($date);
        if ($timestamp < $now - 30 * 86400) unset($stats[$date]);
    }
    if (!isset($stats[$today])) {
        $stats[$today] = [
            'ai_calls' => 0, 'explain_calls' => 0, 'cache_hits' => 0,
            'ai_ip_count' => 0, 'new_vips' => 0, 'active_ip_count' => 0,
            'ai_ips' => [], 'active_ips' => []
        ];
    }
    $stats[$today]['ai_calls']++;
    if (!isset($stats[$today]['ai_ips'][$ip])) {
        $stats[$today]['ai_ips'][$ip] = 1;
        $stats[$today]['ai_ip_count']++;
    }
    if (!isset($stats[$today]['active_ips'][$ip])) {
        $stats[$today]['active_ips'][$ip] = 1;
        $stats[$today]['active_ip_count']++;
    }
    writeAndUnlock($fp, $stats);
}
// 访问日志
writeAccessLog([
    'request_id' => $request_id,
    'time' => date('Y-m-d H:i:s'),
    'device_hash' => $device_log_id,
    'ip_mask' => substr($ip, 0, (int)strrpos($ip, '.') + 2) . '*',
    'is_vip' => $is_vip,
    'action' => 'full',
    'mode' => $mode,
    'model_used' => $used_model,
    'text_len' => $text_len,
    'ai_cost_ms' => $ai_cost_ms,
    'total_cost_ms' => round((microtime(true) - $request_start_time) * 1000)
]);
// ===== 返回结果 =====
echo json_encode([
    'code' => 0,
    'request_id' => $request_id,
    'data' => $ai_data,
    'model' => $used_model
]);