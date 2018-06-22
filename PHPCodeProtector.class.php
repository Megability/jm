<?php
// PHP源码加密类 v1.0
class PHPCodeProtector
{
    private $expire               = 0;
    private $expire_msg           = 'PHPCode Expired!';
    private $allow_ip;
    private $allow_domain;
    private $not_allow_ip_msg     = 'PHPCode Not Allow Run On This Ip!';
    private $not_allow_domain_msg = 'PHPCode Not Allow Run On This Domain!';
    private $separator            = ',';
    private $key                  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    private $comment;
    private $code;

    function __construct()
    {
        //
    }

    // 加载文件
    public function load($code='', $isfile=0)
    {
        if($isfile && file_exists($code)){
            $this->code = file_get_contents($code);
        }else{
            $this->code = $code;
        }
    }

    // 输出
    public function output($highlight=0)
    {
        $content = $this->_crypt($this->code);
        return $highlight ? highlight_string($content) : $content;
    }

    // 另存为
    public function render($filename='', $type="text/plain", $expire=180)
    {
        if(!$filename){
            $filename = 'pcp_'.time().'php';
        }
        // 加密后代码
        $content = $this->output();
        $length = strlen($content);

        //发送Http Header信息 开始下载
        header("Pragma: public");
        header("Cache-control: max-age=".$expire);
        //header('Cache-Control: no-store, no-cache, must-revalidate');
        header("Expires: " . gmdate("D, d M Y H:i:s",time()+$expire) . "GMT");
        header("Last-Modified: " . gmdate("D, d M Y H:i:s",time()) . "GMT");
        header("Content-Disposition: attachment; filename=".$filename);
        header("Content-Length: ".$length);
        header("Content-type: ".$type);
        header('Content-Encoding: none');
        header("Content-Transfer-Encoding: binary" );
        echo $content;
        exit;
    }

    // 保存
    public function save($file='')
    {
        $content = $this->output();
        return file_put_contents($file, $content);
    }

    // 版本注释
    public function setCopyright($copyright='')
    {
        if(!empty($copyright)){
            $this->copyright = $copyright;
        }
    }

    // 设置超时
    public function setExpire($expire=null, $expire_msg='PHPCode Expired!')
    {
        if(!is_null($expire)){
            $this->expire = $expire;
        }
        if(!empty($expire_msg)){
            $this->expire_msg = $expire_msg;
        }
    }

    // 设置允许IP
    public function setAllowIp($allow_ip='', $not_allow_ip_msg='PHPCode Not Allow Run On This Ip!')
    {
        if(!empty($allow_ip)){
            $this->allow_ip = $allow_ip;
        }
        if(!empty($not_allow_ip_msg)){
            $this->not_allow_ip_msg = $not_allow_ip_msg;
        }
    }

    // 设置允许域名
    public function setAllowDomain($allow_domain='', $not_allow_domain_msg='PHPCode Not Allow Run On This Domain!')
    {
        if(!empty($allow_domain)){
            $this->allow_domain = $allow_domain;
        }
        if(!empty($not_allow_domain_msg)){
            $this->not_allow_domain_msg = $not_allow_domain_msg;
        }
    }

    // 设置密匙
    public function setKey($key)
    {
        $this->key = $key;
    }

    // 获取随机密匙
    private function _getRandKey()
    {
        return str_shuffle($this->key);
    }

    // 加密
    private function _crypt($php_code='')
    {
        // 随机密匙1
        $rand_key1 = $this->_getRandKey();
        // 随机密匙2
        $rand_key2 = $this->_getRandKey();

        // 加入时间限制
        if($this->expire > 0){
            $verify_code .= 'if(time() > '.$this->expire.') die(\''.$this->expire_msg.'\');';
        }
        // 加入IP限制
        $allow_ips = explode($this->separator, $this->allow_ip);
        $allow_ips = array_filter($allow_ips);
        if(is_array($allow_ips) && !empty($allow_ips)){
            $verify_code .= 'if(!in_array($_SERVER["SERVER_ADDR"], '.str_replace("\n", '', var_export($allow_ips, true)).')) die(\''.$this->not_allow_ip_msg.'\');';
        }
        // 加入域名限制
        $allow_domains = explode($this->separator, $this->allow_domain);
        $allow_domains = array_filter($allow_domains);
        if(is_array($allow_domains) && !empty($allow_domains)){
            $verify_code .= 'if(!in_array($_SERVER["HTTP_HOST"], '.str_replace("\n", '', var_export($allow_domains, true)).')) die(\''.$this->not_allow_domain_msg.'\');';
        }
        // 验证信息
        $verify_code = $verify_code ? '<?php ' . $verify_code . '?>' : '';

        // PHP源码
        $php_code = $verify_code.$php_code;
        // 代码压缩
        $php_code = $this->_compressPhpSrc($php_code);

        // base64加密
        $base64_str = base64_encode($php_code);
        // 根据密匙替换对应字符
        $c = strtr($base64_str, $rand_key1, $rand_key2);
        $c = $rand_key1.$rand_key2.$c;
        $q1 = "O00O0O";
        $q2 = "O0O000";
        $q3 = "O0OO00";
        $q4 = "OO0O00";
        $q5 = "OO0000";
        $q6 = "O00OO0";
        $s = '$'.$q6.'=urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A");$'
            .$q1.'=$'.$q6.'{3}.$'.$q6.'{6}.$'.$q6.'{33}.$'.$q6.'{30};$'
            .$q3.'=$'.$q6.'{33}.$'.$q6.'{10}.$'.$q6.'{24}.$'.$q6.'{10}.$'.$q6.'{24};$'
            .$q4.'=$'.$q3.'{0}.$'.$q6.'{18}.$'.$q6.'{3}.$'.$q3.'{0}.$'.$q3.'{1}.$'.$q6.'{24};$'
            .$q5.'=$'.$q6.'{7}.$'.$q6.'{13};$'
            .$q1.'.=$'.$q6.'{22}.$'.$q6.'{36}.$'.$q6.'{29}.$'.$q6.'{26}.$'.$q6.'{30}.$'.$q6.'{32}.$'.$q6.'{35}.$'.$q6.'{26}.$'.$q6.'{30};eval($'
            .$q1.'("'.base64_encode('$'.$q2.'="'.$c.'";eval(\'?>\'.$'.$q1.'($'.$q3.'($'.$q4.'($'.$q2.',$'.$q5.'*2),$'.$q4.'($'.$q2.',$'.$q5.',$'.$q5.'),$'.$q4.'($'.$q2.',0,$'.$q5.'))));').'"));';
        $code = '<?php ';
        if(!empty($this->copyright)){
            $code .= '/* '.$this->copyright.' */ ';
        }
        $code .= $s;
        // 返回
        return $code;
    }

    // PHP代码压缩
    function _compressPhpSrc($src)
    {
        // Whitespaces left and right from this signs can be ignored
        static $IW = array(
            T_CONCAT_EQUAL,             // .=
            T_DOUBLE_ARROW,             // =>
            T_BOOLEAN_AND,              // &&
            T_BOOLEAN_OR,               // ||
            T_IS_EQUAL,                 // ==
            T_IS_NOT_EQUAL,             // != or <>
            T_IS_SMALLER_OR_EQUAL,      // <=
            T_IS_GREATER_OR_EQUAL,      // >=
            T_INC,                      // ++
            T_DEC,                      // --
            T_PLUS_EQUAL,               // +=
            T_MINUS_EQUAL,              // -=
            T_MUL_EQUAL,                // *=
            T_DIV_EQUAL,                // /=
            T_IS_IDENTICAL,             // ===
            T_IS_NOT_IDENTICAL,         // !==
            T_DOUBLE_COLON,             // ::
            T_PAAMAYIM_NEKUDOTAYIM,     // ::
            T_OBJECT_OPERATOR,          // ->
            T_DOLLAR_OPEN_CURLY_BRACES, // ${
            T_AND_EQUAL,                // &=
                T_MOD_EQUAL,                // %=
                T_XOR_EQUAL,                // ^=
                T_OR_EQUAL,                 // |=
                T_SL,                       // <<
                T_SR,                       // >>
                T_SL_EQUAL,                 // <<=
                T_SR_EQUAL,                 // >>=
            );
            $tokens = token_get_all($src);

            $new = "";
            $c = sizeof($tokens);
            $iw = false; // ignore whitespace
            $ih = false; // in HEREDOC
            $ls = "";    // last sign
            $ot = null;  // open tag
            for($i = 0; $i < $c; $i++) {
                $token = $tokens[$i];
                if(is_array($token)) {
                    list($tn, $ts) = $token; // tokens: number, string, line
                    $tname = token_name($tn);
                    if($tn == T_INLINE_HTML) {
                        $new .= $ts;
                        $iw = false;
                    } else {
                        if($tn == T_OPEN_TAG) {
                            if(strpos($ts, " ") || strpos($ts, "\n") || strpos($ts, "\t") || strpos($ts, "\r")) {
                                $ts = rtrim($ts);
                            }
                            $ts .= " ";
                            $new .= $ts;
                            $ot = T_OPEN_TAG;
                            $iw = true;
                        } elseif($tn == T_OPEN_TAG_WITH_ECHO) {
                            $new .= $ts;
                            $ot = T_OPEN_TAG_WITH_ECHO;
                            $iw = true;
                        } elseif($tn == T_CLOSE_TAG) {
                            if($ot == T_OPEN_TAG_WITH_ECHO) {
                                $new = rtrim($new, "; ");
                            } else {
                                $ts = " ".$ts;
                            }
                            $new .= $ts;
                            $ot = null;
                            $iw = false;
                        } elseif(in_array($tn, $IW)) {
                            $new .= $ts;
                            $iw = true;
                        } elseif($tn == T_CONSTANT_ENCAPSED_STRING
                            || $tn == T_ENCAPSED_AND_WHITESPACE)
                        {
                            if($ts[0] == '"') {
                                $ts = addcslashes($ts, "\n\t\r");
                            }
                            $new .= $ts;
                            $iw = true;
                        } elseif($tn == T_WHITESPACE) {
                            $nt = @$tokens[$i+1];
                            if(!$iw && (!is_string($nt) || $nt == '$') && !in_array($nt[0], $IW)) {
                                $new .= " ";
                            }
                            $iw = false;
                        } elseif($tn == T_START_HEREDOC) {
                            $new .= "<<<S\n";
                            $iw = false;
                            $ih = true; // in HEREDOC
                        } elseif($tn == T_END_HEREDOC) {
                            $new .= "S;";
                            $iw = true;
                            $ih = false; // in HEREDOC
                            for($j = $i+1; $j < $c; $j++) {
                                if(is_string($tokens[$j]) && $tokens[$j] == ";") {
                                    $i = $j;
                                    break;
                                } else if($tokens[$j][0] == T_CLOSE_TAG) {
                                    break;
                                }
                            }
                        } elseif($tn == T_COMMENT || $tn == T_DOC_COMMENT) {
                            $iw = true;
                        } else {
                            if(!$ih) {
                                $ts = strtolower($ts);
                            }
                            $new .= $ts;
                            $iw = false;
                        }
                    }
                    $ls = "";
                } else {
                    if(($token != ";" && $token != ":") || $ls != $token) {
                        $new .= $token;
                        $ls = $token;
                    }
                    $iw = true;
                }
            }
            return $new;
    }
}