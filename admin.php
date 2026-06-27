<?php
// 会话安全配置
ini_set('session.cookie_httponly', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.gc_maxlifetime', 1800);
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
    ini_set('session.cookie_secure', 1);
}
session_start();

header('Content-Type: text/html; charset=utf-8');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

// 会话活跃度校验
if (isset($_SESSION['modu_admin']) && $_SESSION['modu_admin'] === true) {
    if (!isset($_SESSION['last_activity']) || time() - $_SESSION['last_activity'] > 1800) {
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    $_SESSION['last_activity'] = time();
}

// 数据目录
$data_dir = dirname(__DIR__) . '/modu_data';
$log_dir = dirname(__DIR__) . '/modu_log';
if (!is_dir($data_dir)) mkdir($data_dir, 0700, true);
if (!is_dir($log_dir)) mkdir($log_dir, 0700, true);

$data_file = $data_dir . '/code_data.json';
$token_file = $data_dir . '/vip_tokens.json';
$ip_limit_file = $data_dir . '/redeem_ip_limit.json';
$stats_file = $data_dir . '/stats.json';
$admin_hash_file = $data_dir . '/admin_hash.txt';
$login_fail_file = $data_dir . '/login_fail.json';
$install_pwd_file = $data_dir . '/install_password.txt';

// 初始化数据文件
foreach ([$data_file, $token_file, $ip_limit_file, $stats_file, $login_fail_file] as $f) {
    if (!file_exists($f)) {
        file_put_contents($f, json_encode([], JSON_UNESCAPED_UNICODE));
    }
}

// 首次安装生成随机密码
$first_install = false;
if (!file_exists($admin_hash_file)) {
    $initial_password = bin2hex(random_bytes(8));
    $default_hash = password_hash($initial_password, PASSWORD_DEFAULT);
    file_put_contents($admin_hash_file, $default_hash);
    file_put_contents($install_pwd_file, $initial_password);
    chmod($install_pwd_file, 0600);
    $first_install = true;
}
$admin_hash = trim(file_get_contents($admin_hash_file));

// IP脱敏
function maskIp($ip) {
    if (!$ip || $ip === 'unknown') return '-';
    $parts = explode('.', $ip);
    if (count($parts) === 4) {
        return $parts[0] . '.' . $parts[1] . '.*.*';
    }
    return $ip;
}

// 加锁读写
function lockAndRead($file) {
    $fp = fopen($file, 'c+');
    if (!$fp) return [null, null];
    flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $data = json_decode($raw, true) ?: [];
    return [$fp, $data];
}
function writeAndUnlock($fp, $data) {
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_UNESCAPED_UNICODE));
    flock($fp, LOCK_UN);
    fclose($fp);
}

// CSRF令牌
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
}
$csrf_token = $_SESSION['csrf_token'];
function verifyCsrf($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// 登录状态
$is_login = isset($_SESSION['modu_admin']) && $_SESSION['modu_admin'] === true;
$login_error = '';
$oper_msg = '';
$oper_error = false;

// 登录逻辑
if (!$is_login && isset($_POST['login'])) {
    $password = $_POST['password'] ?? '';
    $client_csrf = $_POST['csrf'] ?? '';
    
    if (!verifyCsrf($client_csrf)) {
        $login_error = '请求非法，请刷新重试';
    } else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        list($fp, $failData) = lockAndRead($login_fail_file);
        if ($fp) {
            $now = time();
            if (!isset($failData[$ip]) || $now - $failData[$ip]['time'] > 900) {
                $failData[$ip] = ['count' => 0, 'time' => $now];
            }
            if ($failData[$ip]['count'] >= 5) {
                writeAndUnlock($fp, $failData);
                $login_error = '密码错误次数过多，请15分钟后再试';
            } elseif (password_verify($password, $admin_hash)) {
                $failData[$ip] = ['count' => 0, 'time' => $now];
                writeAndUnlock($fp, $failData);
                $_SESSION['modu_admin'] = true;
                $_SESSION['login_ip'] = $ip;
                $_SESSION['last_activity'] = time();
                $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
                // 首次登录删除初始密码文件
                if (file_exists($GLOBALS['install_pwd_file'])) {
                    @unlink($GLOBALS['install_pwd_file']);
                }
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
            } else {
                $failData[$ip]['count']++;
                $failData[$ip]['time'] = $now;
                writeAndUnlock($fp, $failData);
                $login_error = '密码错误';
            }
        } else {
            $login_error = '系统异常';
        }
    }
}

// 登出
if ($is_login && isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// 修改密码
$msg = '';
if ($is_login && isset($_POST['change_password'])) {
    if (!verifyCsrf($_POST['csrf'] ?? '')) {
        $msg = '请求非法';
    } else {
        $old = $_POST['old_password'] ?? '';
        $new = $_POST['new_password'] ?? '';
        if (password_verify($old, $admin_hash)) {
            if (strlen($new) >= 8) {
                $new_hash = password_hash($new, PASSWORD_DEFAULT);
                file_put_contents($admin_hash_file, $new_hash);
                $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
                $msg = '密码修改成功！';
            } else {
                $msg = '新密码至少8位';
            }
        } else {
            $msg = '旧密码错误';
        }
    }
}

// 前端兑换接口
if (isset($_POST['action']) && $_POST['action'] === 'redeem') {
    header('Content-Type: application/json; charset=utf-8');
    
    $code = strtoupper(trim($_POST['code'] ?? ''));
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    if (!preg_match('/^[A-Z2-9]{8}$/', $code)) {
        echo json_encode(['code' => 400, 'msg' => '兑换码格式错误']);
        exit;
    }
    
    // IP频率限制
    list($fp, $limit_data) = lockAndRead($ip_limit_file);
    if (!$fp) {
        echo json_encode(['code' => 500, 'msg' => '服务异常']);
        exit;
    }
    $now = time();
    if (!isset($limit_data[$ip]) || $now - $limit_data[$ip]['time'] > 600) {
        $limit_data[$ip] = ['count' => 0, 'time' => $now];
    }
    if ($limit_data[$ip]['count'] >= 5) {
        writeAndUnlock($fp, $limit_data);
        echo json_encode(['code' => 429, 'msg' => '尝试次数过多，请10分钟后再试']);
        exit;
    }
    $limit_data[$ip]['count']++;
    writeAndUnlock($fp, $limit_data);
    
    // 兑换核心流程
    list($fp, $codeData) = lockAndRead($data_file);
    if (!$fp) {
        echo json_encode(['code' => 500, 'msg' => '服务异常']);
        exit;
    }
    if (!isset($codeData['codes'])) $codeData['codes'] = [];
    
    $target = null;
    foreach ($codeData['codes'] as &$item) {
        if ($item['code'] === $code) {
            $target = &$item;
            break;
        }
    }
    
    if ($target === null) {
        writeAndUnlock($fp, $codeData);
        echo json_encode(['code' => 400, 'msg' => '兑换码无效']);
        exit;
    }
    if ($target['used']) {
        writeAndUnlock($fp, $codeData);
        echo json_encode(['code' => 400, 'msg' => '该兑换码已被使用']);
        exit;
    }
    
    $target['used'] = true;
    $target['use_time'] = date('Y-m-d H:i:s');
    $target['use_ip'] = $ip;
    $days = intval($target['days']);
    writeAndUnlock($fp, $codeData);
    
    // 签发VIP Token
    $expireTs = time() + $days * 86400;
    $vipToken = bin2hex(random_bytes(32));
    
    list($fp, $tokenAll) = lockAndRead($token_file);
    if ($fp) {
        $tokenAll[$vipToken] = [
            'expire' => $expireTs,
            'create_at' => time(),
            'days' => $days,
            'create_ip' => $ip,
            'devices' => []
        ];
        writeAndUnlock($fp, $tokenAll);
    }
    
    // 更新统计
    list($fp, $stats) = lockAndRead($stats_file);
    if ($fp) {
        $today = date('Y-m-d');
        if (!isset($stats[$today])) {
            $stats[$today] = [
                'ai_calls' => 0, 'ai_ip_count' => 0,
                'new_vips' => 0, 'active_ip_count' => 0,
                'ai_ips' => [], 'active_ips' => []
            ];
        }
        $stats[$today]['new_vips']++;
        if (!isset($stats[$today]['active_ips'][$ip])) {
            $stats[$today]['active_ips'][$ip] = 1;
            $stats[$today]['active_ip_count']++;
        }
        writeAndUnlock($fp, $stats);
    }
    
    echo json_encode([
        'code' => 0,
        'msg' => '兑换成功',
        'data' => [
            'vip_token' => $vipToken,
            'days' => $days,
            'expire' => $expireTs
        ]
    ]);
    exit;
}

// 后台操作
if ($is_login) {
    // 批量生成兑换码
    if (isset($_POST['generate'])) {
        if (!verifyCsrf($_POST['csrf'] ?? '')) {
            $oper_msg = '请求非法';
            $oper_error = true;
        } else {
            $days = max(1, intval($_POST['days']));
            $count = min(200, max(1, intval($_POST['count'])));
            $remark = trim($_POST['remark'] ?? '');
            
            list($fp, $originData) = lockAndRead($data_file);
            if (!$fp) {
                $oper_msg = '生成失败：数据文件不可写';
                $oper_error = true;
            } else {
                $existingCodes = [];
                if (isset($originData['codes'])) {
                    foreach ($originData['codes'] as $item) {
                        $existingCodes[$item['code']] = true;
                    }
                }
                
                $new_codes = [];
                $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
                $charLen = strlen($chars);
                $attempts = 0;
                $maxAttempts = $count * 10;
                
                while (count($new_codes) < $count && $attempts < $maxAttempts) {
                    $bytes = random_bytes(8);
                    $code_str = '';
                    for ($j = 0; $j < 8; $j++) {
                        $code_str .= $chars[ord($bytes[$j]) % $charLen];
                    }
                    if (!isset($existingCodes[$code_str])) {
                        $existingCodes[$code_str] = true;
                        $new_codes[] = [
                            'code' => $code_str,
                            'days' => $days,
                            'remark' => $remark,
                            'used' => false,
                            'create_time' => date('Y-m-d H:i:s'),
                            'use_time' => '',
                            'use_ip' => ''
                        ];
                    }
                    $attempts++;
                }
                
                if (!empty($new_codes)) {
                    if (!isset($originData['codes'])) $originData['codes'] = [];
                    $originData['codes'] = array_merge($new_codes, $originData['codes']);
                    writeAndUnlock($fp, $originData);
                    $oper_msg = "成功生成 " . count($new_codes) . " 个兑换码";
                } else {
                    writeAndUnlock($fp, $originData);
                    $oper_msg = '生成失败：无法生成唯一兑换码，请重试';
                    $oper_error = true;
                }
            }
        }
    }
    
    // 删除兑换码
    if (isset($_GET['del'])) {
        $del_code = $_GET['del'];
        $csrf = $_GET['csrf'] ?? '';
        if (!verifyCsrf($csrf)) {
            $oper_msg = '请求非法';
            $oper_error = true;
        } else {
            list($fp, $originData) = lockAndRead($data_file);
            if ($fp) {
                $found = false;
                if (!isset($originData['codes'])) $originData['codes'] = [];
                foreach ($originData['codes'] as $k => $v) {
                    if ($v['code'] === $del_code) {
                        unset($originData['codes'][$k]);
                        $found = true;
                        break;
                    }
                }
                if ($found) {
                    $originData['codes'] = array_values($originData['codes']);
                    writeAndUnlock($fp, $originData);
                    header('Location: ' . $_SERVER['PHP_SELF']);
                    exit;
                } else {
                    writeAndUnlock($fp, $originData);
                }
            }
        }
    }
    
    // 读取统计数据
    $codeData = json_decode(file_get_contents($data_file), true) ?: ['codes' => []];
    $total_codes = count($codeData['codes']);
    $used_codes = count(array_filter($codeData['codes'], fn($v) => $v['used']));
    $unused_codes = $total_codes - $used_codes;
    
    $stats = json_decode(file_get_contents($stats_file), true) ?: [];
    $total_ai_calls = 0;
    $total_vips = $used_codes;
    $today = date('Y-m-d');
    $today_calls = isset($stats[$today]) ? ($stats[$today]['ai_calls'] ?? 0) : 0;
    $today_vips = isset($stats[$today]) ? ($stats[$today]['new_vips'] ?? 0) : 0;
    $today_actives = isset($stats[$today]) ? ($stats[$today]['active_ip_count'] ?? 0) : 0;
    
    foreach ($stats as $day) {
        $total_ai_calls += $day['ai_calls'] ?? 0;
    }
    
    // 近7天趋势
    $last7days = [];
    $max_calls = 0;
    for ($i = 6; $i >= 0; $i--) {
        $date = date('Y-m-d', strtotime("-{$i} day"));
        $day_data = isset($stats[$date]) ? $stats[$date] : [
            'ai_calls' => 0, 'new_vips' => 0, 'active_ip_count' => 0
        ];
        $day_data['date_short'] = substr($date, 5);
        $last7days[] = $day_data;
        if ($day_data['ai_calls'] > $max_calls) $max_calls = $day_data['ai_calls'];
    }
    if ($max_calls == 0) $max_calls = 1;
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>墨读 · 管理后台</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background:#f7f5f0; font-family:-apple-system, "PingFang SC", sans-serif; padding:20px; color:#2c2824; }
        .container { max-width:1000px; margin:0 auto; background:#fff; border-radius:20px; padding:28px; box-shadow:0 8px 40px rgba(0,0,0,0.05); margin-bottom:24px; }
        .header { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; padding-bottom:16px; border-bottom:1px solid #f0ede8; }
        .header h1 { font-size:22px; font-weight:500; }
        .logout { color:#8a8078; text-decoration:none; font-size:14px; }
        .section-title { font-size:16px; font-weight:500; margin:24px 0 16px; padding-left:8px; border-left:3px solid #b86b3a; }
        .stats-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:8px; }
        .stat-card { background:#fcfbf9; padding:20px 16px; border-radius:16px; }
        .stat-card .num { font-size:26px; font-weight:500; color:#b86b3a; margin-bottom:4px; }
        .stat-card .label { font-size:13px; color:#8a8078; }
        .stat-card.today .num { color:#4a7a3a; }
        .chart-box { background:#fcfbf9; padding:20px; border-radius:16px; }
        .chart-row { display:flex; align-items:flex-end; gap:12px; height:120px; margin-bottom:8px; }
        .chart-bar-wrap { flex:1; display:flex; flex-direction:column; align-items:center; height:100%; justify-content:flex-end; }
        .chart-bar { width:100%; max-width:40px; background:linear-gradient(to top, #b86b3a, #d49a6a); border-radius:6px 6px 0 0; transition:height 0.3s; min-height:2px; }
        .chart-date { font-size:12px; color:#8a8078; margin-top:6px; }
        .chart-legend { display:flex; gap:20px; font-size:12px; color:#8a8078; margin-top:12px; padding-top:12px; border-top:1px solid #f0ede8; }
        .chart-legend span { display:flex; align-items:center; gap:6px; }
        .legend-dot { width:10px; height:10px; border-radius:50%; }
        .dot-call { background:#b86b3a; }
        .dot-vip { background:#4a7a3a; }
        .dot-active { background:#8a8078; }
        .form-box { background:#fcfbf9; padding:20px; border-radius:16px; }
        .form-row { display:flex; gap:16px; align-items:flex-end; flex-wrap:wrap; }
        .form-item { flex:1; min-width:120px; }
        .form-item label { display:block; font-size:13px; color:#8a8078; margin-bottom:6px; }
        .form-item input { width:100%; padding:10px 12px; border:1px solid #e0dad4; border-radius:10px; font-size:14px; font-family:inherit; background:#fff; }
        .btn-primary { background:#b86b3a; color:#fff; border:none; padding:10px 24px; border-radius:40px; font-size:14px; cursor:pointer; font-family:inherit; }
        .btn-danger { background:transparent; color:#c26b5c; border:1px solid #e6c8c0; padding:4px 10px; border-radius:20px; font-size:12px; cursor:pointer; font-family:inherit; }
        table { width:100%; border-collapse:collapse; font-size:14px; }
        th, td { padding:12px 10px; text-align:left; border-bottom:1px solid #f0ede8; }
        th { font-weight:500; color:#8a8078; font-size:13px; background:#fcfbf9; }
        .status { display:inline-block; padding:2px 10px; border-radius:12px; font-size:12px; }
        .status.unused { background:#d4e0d0; color:#4a7a3a; }
        .status.used { background:#e8e2da; color:#8a8078; }
        .msg { color:#4a7a3a; margin-bottom:16px; }
        .msg.error { color:#c26b5c; }
        .login-box { max-width:400px; margin:80px auto; background:#fff; padding:40px 32px; border-radius:24px; box-shadow:0 8px 40px rgba(0,0,0,0.08); text-align:center; }
        .login-box h2 { font-size:20px; font-weight:500; margin-bottom:24px; }
        .login-box input { width:100%; padding:14px; border:1px solid #e0dad4; border-radius:12px; font-size:15px; margin-bottom:16px; font-family:inherit; }
        .tip { font-size:12px; color:#b0a8a0; margin-top:8px; }
        .initial-pwd { background:#fff8e6; border:1px solid #f0d890; color:#8a6d1a; padding:12px 16px; border-radius:12px; margin-bottom:16px; text-align:left; }
        .initial-pwd code { background:#fff; padding:2px 8px; border-radius:6px; font-family:monospace; }
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns:repeat(2,1fr); }
        }
    </style>
</head>
<body>
<?php if (!$is_login): ?>
<div class="login-box">
    <h2>🔐 管理员登录</h2>
    <?php if ($first_install && file_exists($install_pwd_file)): ?>
    <div class="initial-pwd">
        ⚠️ 首次安装，系统已生成临时密码，保存在<br>
        <code>modu_data/install_password.txt</code><br>
        <span style="font-size:12px;">登录后文件将自动删除，请及时修改密码</span>
    </div>
    <?php endif; ?>
    <?php if ($login_error): ?><div class="msg error"><?= htmlspecialchars($login_error) ?></div><?php endif; ?>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf_token) ?>">
        <input type="password" name="password" placeholder="请输入管理员密码" required autofocus>
        <button type="submit" name="login" class="btn-primary" style="width:100%;padding:14px;font-size:15px;">登录</button>
    </form>
    <div class="tip">连续5次错误将锁定15分钟</div>
</div>
<?php else: ?>
<!-- 数据看板 -->
<div class="container">
    <div class="header">
        <h1>📊 运营数据概览</h1>
        <a href="?action=logout" class="logout">退出登录</a>
    </div>
    <?php if ($msg): ?><div class="msg"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <?php if ($oper_msg): ?><div class="msg <?= $oper_error ? 'error' : '' ?>"><?= htmlspecialchars($oper_msg) ?></div><?php endif; ?>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="num"><?= $total_ai_calls ?></div>
            <div class="label">累计AI调用量</div>
        </div>
        <div class="stat-card">
            <div class="num"><?= $total_vips ?></div>
            <div class="label">累计会员数</div>
        </div>
        <div class="stat-card today">
            <div class="num"><?= $today_calls ?></div>
            <div class="label">今日AI调用</div>
        </div>
        <div class="stat-card today">
            <div class="num"><?= $today_vips ?></div>
            <div class="label">今日新增会员</div>
        </div>
    </div>
    
    <div class="section-title">近7天趋势</div>
    <div class="chart-box">
        <div class="chart-row">
            <?php foreach ($last7days as $day): ?>
            <div class="chart-bar-wrap">
                <div class="chart-bar" style="height: <?= round(($day['ai_calls'] / $max_calls) * 100) ?>%"></div>
                <div class="chart-date"><?= $day['date_short'] ?></div>
            </div>
            <?php endforeach; ?>
        </div>
        <div class="chart-legend">
            <span><i class="legend-dot dot-call"></i> AI调用量</span>
            <span><i class="legend-dot dot-vip"></i> 新增会员</span>
            <span><i class="legend-dot dot-active"></i> 活跃IP</span>
        </div>
        <table style="margin-top:12px;">
            <thead>
                <tr><th>日期</th><th>AI调用量</th><th>新增会员</th><th>活跃IP数</th></tr>
            </thead>
            <tbody>
                <?php foreach (array_reverse($last7days) as $day): ?>
                <tr>
                    <td><?= htmlspecialchars($day['date_short']) ?></td>
                    <td><?= intval($day['ai_calls']) ?></td>
                    <td><?= intval($day['new_vips']) ?></td>
                    <td><?= intval($day['active_ip_count']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- 兑换码管理 -->
<div class="container">
    <div class="section-title" style="margin-top:0;">🎫 兑换码管理</div>
    <div class="stats-grid" style="grid-template-columns:repeat(3,1fr);">
        <div class="stat-card">
            <div class="num"><?= $total_codes ?></div>
            <div class="label">总兑换码</div>
        </div>
        <div class="stat-card">
            <div class="num"><?= $unused_codes ?></div>
            <div class="label">未使用</div>
        </div>
        <div class="stat-card">
            <div class="num"><?= $used_codes ?></div>
            <div class="label">已使用</div>
        </div>
    </div>
    
    <div class="form-box" style="margin-top:20px;">
        <h3 style="font-size:16px;font-weight:500;margin-bottom:16px;">批量生成兑换码</h3>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf_token) ?>">
            <div class="form-row">
                <div class="form-item">
                    <label>有效天数</label>
                    <input type="number" name="days" value="30" min="1" required>
                </div>
                <div class="form-item">
                    <label>生成数量</label>
                    <input type="number" name="count" value="10" min="1" max="200" required>
                </div>
                <div class="form-item" style="flex:2;">
                    <label>备注（可选）</label>
                    <input type="text" name="remark" placeholder="如：首发放量、活动赠送">
                </div>
                <div class="form-item" style="flex:none;">
                    <button type="submit" name="generate" class="btn-primary">生成</button>
                </div>
            </div>
        </form>
    </div>
    
    <div style="margin-top:24px;">
        <h3 style="font-size:16px;font-weight:500;margin-bottom:16px;">兑换码列表</h3>
        <div style="overflow-x:auto;">
            <table>
                <thead>
                    <tr>
                        <th>兑换码</th>
                        <th>天数</th>
                        <th>状态</th>
                        <th>备注</th>
                        <th>生成时间</th>
                        <th>使用时间</th>
                        <th>使用IP</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($codeData['codes'] as $item): ?>
                    <tr>
                        <td style="font-family:monospace;letter-spacing:1px;"><?= htmlspecialchars($item['code']) ?></td>
                        <td><?= intval($item['days']) ?> 天</td>
                        <td>
                            <span class="status <?= $item['used'] ? 'used' : 'unused' ?>">
                                <?= $item['used'] ? '已使用' : '未使用' ?>
                            </span>
                        </td>
                        <td><?= htmlspecialchars($item['remark']) ?></td>
                        <td style="color:#8a8078;font-size:13px;"><?= htmlspecialchars($item['create_time']) ?></td>
                        <td style="color:#8a8078;font-size:13px;"><?= $item['use_time'] ? htmlspecialchars($item['use_time']) : '-' ?></td>
                        <td style="color:#8a8078;font-size:13px;"><?= maskIp($item['use_ip'] ?? '') ?></td>
                        <td>
                            <?php if (empty($item['used'])): ?>
                            <a href="?del=<?= urlencode($item['code']) ?>&csrf=<?= urlencode($csrf_token) ?>" onclick="return confirm('确定删除该兑换码？删除后不可恢复')">
                                <button type="button" class="btn-danger">删除</button>
                            </a>
                            <?php else: ?>
                            -
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($codeData['codes'])): ?>
                    <tr>
                        <td colspan="8" style="text-align:center;color:#b0a8a0;padding:40px;">暂无兑换码</td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
    
    <div class="section-title">🔑 修改管理员密码</div>
    <div class="form-box">
        <form method="post">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf_token) ?>">
            <div class="form-row">
                <div class="form-item">
                    <label>当前密码</label>
                    <input type="password" name="old_password" required>
                </div>
                <div class="form-item">
                    <label>新密码（≥8位）</label>
                    <input type="password" name="new_password" required>
                </div>
                <div class="form-item" style="flex:none;">
                    <button type="submit" name="change_password" class="btn-primary">修改密码</button>
                </div>
            </div>
        </form>
    </div>
</div>
<?php endif; ?>
</body>
</html>