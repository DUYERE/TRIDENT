<?php
// 正例：请求参数直接进入 SQL 执行接口
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
$result = mysql_query($sql);

// 正例：命令注入与反射型 XSS
$cmd = $request->input('host');
system("ping -c 1 " . $cmd);
echo $_POST['q'];

// 自定义规则锚点（仅在 --rules 指定调用者规则时命中）
debug_log($_GET['debug']);

// 负例：显式数值转换
$safe_page = intval($_GET['page']);
mysql_query("SELECT * FROM pages WHERE id = " . $safe_page);

// 负例：参数绑定（execute 不作为 SQL sink）
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute([':id' => $_GET['id']]);

// 负例：注释与字符串中的代码形状不参与分析
// mysql_query($_GET['id']);
// system($_POST['cmd']);
$note = "mysql_query($_GET[id]) and eval($_POST[q])";

Route::get('/search', function () { return 'ok'; });

// 正例：动态代码执行与不安全反序列化
eval($_GET['code']);
unserialize($_COOKIE['session']);

// 正例（v2）：双引号字符串内的变量插值进入 SQL
$uid = $_GET['uid'];
mysql_query("SELECT * FROM users WHERE uid = $uid");

// 正例（v2）：同文件函数摘要 —— sink 包装器
function runUserQuery($q) {
    mysql_query($q);
}
runUserQuery($_GET['uname']);

// 正例（v2）：同文件函数摘要 —— source 包装器
function readUsername() {
    return $_GET['username'];
}
mysql_query("SELECT * FROM users WHERE name = " . readUsername());

// 正例（v2）：开放重定向与 XPath 注入
header("Location: " . $_GET['to']);
$nodes = $doc->xpath($_GET['expr']);

// 负例（v2）：单引号字符串不插值；净化包装器不产出
$sql2 = 'SELECT * FROM users WHERE uid = $uid';
function runSafeQuery($q) {
    mysql_query(intval($q));
}
runSafeQuery($_GET['page']);
