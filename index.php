<?php
error_reporting(0);
if($_SERVER['REQUEST_METHOD']=='POST'){
    // 导入类
    require 'PHPCodeProtector.class.php';
    // 创建类
    $pcp = new PHPCodeProtector;
    // 加载代码
    $pcp->load($_POST['code']);
    // 设置版本信息
    if($_POST['copyright_on']){
        $pcp->setCopyright($_POST['copyright']);
    }
    // 设置过期时间
    if($_POST['expire_on']){
        $pcp->setExpire(strtotime($_POST['expire']), $_POST['expire_msg']);
    }
    // 设置允许IP
    if($_POST['allow_ip_on']){
        $pcp->setAllowIp($_POST['allow_ip'], $_POST['not_allow_ip_msg']);
    }
    // 设置允许域名
    if($_POST['allow_domain_on']){
        $pcp->setAllowDomain($_POST['allow_domain'], $_POST['not_allow_domain_msg']);
    }
    // 保存至本地
    if($_POST['render_on']){
        $pcp->render($_POST['render_name']);
        exit;
    }
    // 输出加密后的代码
    $code = $pcp->output();
}else{
    $copyright            = 'huangdijia@gmail.com';
    $expire               = date('Y-m-d', strtotime('+1 day'));
    $expire_msg           = 'PHP代码已经过期';
    $allow_ip             = '127.0.0.1,192.168.1.1';
    $not_allow_ip_msg     = 'PHP代码不允许在此IP执行';
    $allow_domain         = 'localhost,www.hdj.me';
    $not_allow_domain_msg = 'PHP代码不允许在此域名执行';
    $render_name          = 'pcp_'.time().'.php';
    $code                 = <<<CODE
<?php
/* Class   PHPCodeProtector */
/* Version 1.0 */
/* Author  Deeka */
/* Email   huangdijia@gmail.com */
echo phpinfo();
?>
CODE;
}
?>
<!DOCTYPE HTML>
<html>
<head>
<meta charset="utf-8">
<title>PHPCodeProtector</title>
<style>
html,body, textarea{ font-size:13px;}
</style>
</head>

<body>
<h1>PHP代码保护</h1>
<p>版本：1.0</p>
<div><b>已知BUG</b></div>
<ul>
    <li>常量会被转为字符串</li>
</ul>
<form method="post" action="?">
    <p>请输入PHP代码：</p>
    <p><textarea name="code" style="width:590px;" cols="30" rows="20"><?php echo $code; ?></textarea></p>
    <p>
        <label><input type="checkbox" name="copyright_on" <?php echo $_POST['copyright_on']?'checked':''?> /> 版本信息：</label>
        <input type="text" name="copyright" value="<?php echo $_POST['copyright']?$_POST['copyright']:$copyright; ?>" />
    </p>
    <p>
        <label><input type="checkbox" name="expire_on" value="1" <?php echo $_POST['expire_on']?'checked':''?> /> 有 效 期：</label>
        <input type="text" name="expire" value="<?php echo $_POST['expire']?$_POST['expire']:$expire;?>" />
        提示：<input type="text" name="expire_msg" size="40" value="<?php echo $_POST['expire_msg']?$_POST['expire_msg']:$expire_msg; ?>" />
    </p>
    <p>
        <label><input type="checkbox" name="allow_ip_on" value="1" <?php echo $_POST['allow_ip_on']?'checked':''?> /> 允 许 IP：</label>
        <input type="text" name="allow_ip" value="<?php echo $_POST['allow_ip']?$_POST['allow_ip']:$allow_ip;?>" />
        提示：<input type="text" name="not_allow_ip_msg" size="40" value="<?php echo $_POST['not_allow_ip_msg']?$_POST['not_allow_ip_msg']:$not_allow_ip_msg;?>" />
    </p>
    <p>
        <label><input type="checkbox" name="allow_domain_on" value="1" <?php echo $_POST['allow_domain_on']?'checked':''?> /> 允许域名：</label>
        <input type="text" name="allow_domain" value="<?php echo $_POST['allow_domain']?$_POST['allow_domain']:$allow_domain;?>" />
        提示：<input type="text" name="not_allow_domain_msg" size="40" value="<?php echo $_POST['not_allow_domain_msg']?$_POST['not_allow_domain_msg']:$not_allow_domain_msg;?>" />
    </p>
    <p>
        <label><input type="checkbox" name="render_on" value="1" /> 保存为：</label>
        <input type="text" name="render_name" value="<?php echo $_POST['render_name']?$_POST['render_name']:$render_name;?>" />
    </p>
    <p>
        <button type="submit">提交</button>
    </p>
</form>
</body>
</html>