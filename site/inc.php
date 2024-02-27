<?php
$cacheDuration = 300;
header("Content-Type: text/plain; charset=utf-8");
header("Cache-Control: max-age={$cacheDuration}");
header('Expires: ' . gmdate('D, d M Y H:i:s \G\M\T', time() + $cacheDuration));

define('VMESS', 'vmess://');
define('VLESS', 'vless://');
define('TROJAN', 'trojan://');


class SubProcessor
{
    private $_shortenSni = [];
    private $suffix;
    private $prefix;
    private $singbox_title;
    private $singbox_template;
    private $singbox_dns;
    private $cfhost;
    private $gchost;
    private $format;
    private $fingerprint;
    private $ipfy;
    private $mangle;
    private $database;
    private $cdnfilter;
    private $fsni;
    private $sni;
    private $resultLines;
    private $fvision;
    private $finsecure;
    private $fgeo;
    private $exfgeo;
    private $fkind;
    private $fsec;
    private $fnet;
    private $fwarp;
    private $fport;
    private int $limit;
    private $dnsCache=[];

    public function __construct()
    {
        $this->limit=intval(@"0{$_GET['limit']}",10);
        $this->suffix = rtrim(@"{$_GET['suffix']}");
        $this->prefix = ltrim(@"{$_GET['prefix']}");
        $this->singbox_title = trim(@"{$_GET['singbox-title']}");
        if ($this->singbox_title === '') $this->singbox_title = 'Sing box subs';
        $this->singbox_template = trim(@"{$_GET['singbox-template']}");
        if ($this->singbox_template === '') $this->singbox_template = 'default';
        $this->singbox_dns = trim(@"{$_GET['singbox-dns']}");
        if ($this->singbox_dns === '') $this->singbox_dns = 'tcp://1.1.1.1';
        $this->cfhost = self::arrayValue('cf-server');
        if (false === $this->cfhost)
            $this->cfhost = ['speed.cloudflare.com'];
        $this->gchost = self::arrayValue('gc-server');
        if (false === $this->gchost)
            $this->gchost = ['gcore.com'];
        $this->format = trim(@"{$_GET['fmt']}");
        if (self::boolFlag('b64')) $this->format = "b64";
        $this->fingerprint = trim(@"{$_GET['fp']}");
        if ($this->fingerprint === '') $this->fingerprint = 'chrome';
        $this->ipfy = self::boolFlag('ipfy');
        $this->mangle = @"{$_GET['mangle']}";

        $tag = strtolower(trim(@"{$_GET['tag']}"));
        if ('' === $tag) $tag = 'freedom';
        if (self::boolFlag('full'))
            $tag = 'full';

        $this->database = '';
        switch ($this->format) {
            case 'singbox':
                $this->database = 'sb-';
                break;
            case 'ss':
                $this->database = 'ss-';
                break;
            default:
                $this->database = '';
                break;
        }

        if ($tag !== 'full')
            $this->database = "{$this->database}proxy-db-{$tag}.lst";
        else
            $this->database = "{$this->database}proxy-db.lst";


        $this->database = "$this->database.gz";


        $this->cdnfilter = self::stringFilter('cdn', '/[^A-Z]+/i');

        $this->fsni = self::arrayValue('sni');
        $this->sni = '';
        if (is_array($this->fsni)) {
            $tmp = [];
            foreach ($this->fsni as $i) self::fillSni($i, $tmp);
            $this->fsni = $tmp;
            unset($tmp);
            unset($i);

            $this->sni = @"{$this->fsni[0]}";
            $this->fsni = array_map(function ($x) {
                return preg_quote($x);
            }, $this->fsni);
            $this->fsni = '/^(?:.*\.)?(?:' . implode('|', $this->fsni) . ')$/mi';
        }
        if ($this->sni === '') $this->sni = 'vkvd127.mycdn.me';
        $this->fvision = self::boolFlag3('vision');
        $this->finsecure = self::boolFlag3('insecure');

        $this->fgeo = self::stringFilter('country', '/[^A-Z]+/i');
        $this->exfgeo = self::stringFilter('excludeCountry', '/[^A-Z]+/i');

        $this->fkind = self::stringFilter('kind', '/[^a-z0-9_]+/');
        if (false !== $this->fkind && false !== stripos($this->fkind, ';ss;'))
            $this->fkind = "{$this->fkind};ss2022;ss_legacy;";

        $this->fsec = self::stringFilter('security', '/[^a-z]+/');
        if (false !== $this->fsec && false !== stripos($this->fsec, ';tls;'))
            $this->fsec = "{$this->fsec}reality;";

        $this->fwarp = self::stringFilter('warp', '/[^a-z]+/');
        if (false !== $this->fwarp && false !== stripos($this->fwarp, ';on;'))
            $this->fsec = "{$this->fwarp}plus;";

        $this->fnet = self::stringFilter('network', '/[^a-z2]+/');

        $this->fport = self::stringFilter('port', '/[^0-9]+/');

        $this->resultLines = [];

    }

    private static function arrayValue($name)
    {
        $tmp = trim(@"{$_GET[$name]}");
        $tmp = explode(';', $tmp);
        $tmp = array_map('trim', $tmp);
        $tmp = array_filter($tmp, function ($i) {
            return $i !== '';
        });
        $tmp = array_values($tmp);
        if (count($tmp) === 0) $tmp = false;
        return $tmp;
    }

    private static function boolFlag($name)
    {
        $cf = trim(@"{$_GET[$name]}");
        $cf = false !== stripos(';1;y;yes;true;on;t;', ";{$cf};");
        return $cf;
    }

    private static function stringFilter($name, $regex)
    {
        $lst = trim(preg_replace($regex, ';', @"{$_GET[$name]}"), ';');
        return $lst === ''
            ? false
            : strtolower(";{$lst};");
    }

    private static function fillSni($i, &$tmp)
    {
        switch (strtolower($i)) {
            case 'mts-sn':
                self::fillSni('mts-ok', $tmp);
                break;
            case 'mts-im':
                self::fillSni('mts-viber', $tmp);
                self::fillSni('mts-telegram', $tmp);
                self::fillSni('mts-skype', $tmp);
                self::fillSni('mts-whatsapp', $tmp);
                self::fillSni('mts-snapchat', $tmp);
                break;
            case 'mts':
                self::fillSni('mts-im', $tmp);
                self::fillSni('mts-sn', $tmp);
                break;
            case 'mts-snapchat':
                $tmp[] = "gcp.api.snapchat.com";
                $tmp[] = "aws.api.snapchat.com";
                $tmp[] = "us-east1-aws-acc.api.snapchat.com";
                break;
            case 'mts-viber':
                $tmp[] = 'dl-media.viber.com';
                $tmp[] = 'content.cdn.viber.com';
                $tmp[] = 'explore.api.viber.com';
                $tmp[] = 'abff.viber.com';
                break;
            case 'mts-ok':
                $tmp[] = 'msgproxy.mycdn.me';
                $tmp[] = 'vkvd127.mycdn.me';
                break;
            case 'mts-skype':
                $tmp[] = "search.skype.com";
                $tmp[] = "msgsearch.skype.com";
                $tmp[] = "avatar.skype.com";
                break;
            case 'mts-whatsapp':
                $tmp[] = 'media-hel3-1.cdn.whatsapp.net';
                $tmp[] = 'static.whatsapp.net';
                break;
            case 'mts-telegram':
                $tmp[] = 'telegram.org';
                break;
            default:
                $tmp[] = $i;
                break;
        }
    }

    private static function boolFlag3($name)
    {
        $cf = trim(@"{$_GET[$name]}");
        if (false !== stripos(';1;y;yes;true;on;t;', ";{$cf};")) return true;
        if (false !== stripos(';0;n;no;false;off;f;', ";{$cf};")) return false;
        return null;
    }

    public static function execute()
    {
        $sp = new SubProcessor();
        $sp->createSub();
    }

    public function createSub()
    {
        $count=0;


        if (false !== $this->cfhost && $this->ipfy === true)
            foreach ($this->cfhost as &$item)
                $item = $this->hostByName($item);
        if (false !== $this->gchost && $this->ipfy === true)
            foreach ($this->gchost as &$item)
                $item = $this->hostByName($item);


//        var_dump($template);
        $lines = self::fcache($this->database);
//        var_dump($lines);
        if (is_array($lines)) {
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '') continue;
                if (0 === strpos($line, '#')) continue;
                $tmp = json_decode($line);
                if (!is_object($tmp)) continue;

                if (false == self::checkFlag3($this->fvision, isset($tmp->vision) && $tmp->vision === true))
                    continue;
                if (false == self::checkFlag3($this->finsecure, isset($tmp->insecure) && $tmp->insecure === true))
                    continue;
                switch ($tmp->k) {
                    case "cf":
                    case "gcore":
                        $cdnname = $tmp->k;
                        break;
                    default:
                        $cdnname = 'none';
                        break;
                }
                if (false !== $this->cdnfilter)
                    if (false === stripos($this->cdnfilter, ";{$cdnname};"))
                        continue;

                if (false !== $this->fkind)
                    if (false === stripos($this->fkind, ";{$tmp->type};"))
                        continue;

                if(!isset($tmp->warp)) $tmp->warp='off';
                if (false !== $this->fwarp)
                    if (false === stripos($this->fwarp, ";{$tmp->warp};"))
                        continue;

                if (false !== $this->fgeo)
                    if (false === stripos($this->fgeo, ";{$tmp->cc};"))
                        continue;
                if (false !== $this->exfgeo)
                    if (false !== stripos($this->exfgeo, ";{$tmp->cc};"))
                        continue;

                if (false !== $this->fnet)
                    if (false === stripos($this->fnet, ";{$tmp->net};"))
                        continue;

                if (false !== $this->fport)
                    if (false === strpos($this->fport, ";{$tmp->port};"))
                        continue;

                if(!isset($tmp->fsec)) $tmp->fsec='none';
                if (false !== $this->fsec)
                    if (false === stripos($this->fsec, ";{$tmp->sec};"))
                        continue;


                $sniOk = $this->fsni === false;
                if ($tmp->k === 'sni') {
                    $sniOk = true;
                    $tmp->sni = $this->sni;
                } elseif ($this->fsni !== false && preg_match($this->fsni, @"{$tmp->sni}"))
                    $sniOk = true;


                if ($sniOk === false)
                    continue;
//                var_dump(9);


                if ($tmp->k === 'cf') {
                    $hashKey = isset($tmp->u) ? $tmp->u : serialize($tmp->oo);
                    $h = self::randomItem($this->cfhost, "{$tmp->sni}|{$hashKey}");
                    if (0 === stripos($h, 'rand:'))
                        $h = self::randomCfHost("{$tmp->sni}|{$hashKey}|{$h}");
                    $tmp->host = $h;
                } elseif ($tmp->k === 'gcore') {
                    $hashKey = isset($tmp->u) ? $tmp->u : serialize($tmp->oo);
                    $h = self::randomItem($this->gchost, "{$tmp->sni}|{$hashKey}");
                    if (0 === stripos($h, 'rand:'))
                        $h = self::randomGcHost("{$tmp->sni}|{$hashKey}|{$h}");
                    $tmp->host = $h;
                } elseif ($this->ipfy) {
                    if (isset($tmp->ip))
                        $tmp->host = $tmp->ip;
                    else
                        $tmp->host = $this->hostByName($tmp->host);
                }

                if ($this->fsni === false && strlen($this->mangle) !== 0 && @"{$tmp->sni}" !== '') {
                    $tmp->sni = self::mangle(@"{$tmp->sni}", $this->mangle);
                }

                $title = $tmp->t;
                if ($this->suffix !== '') {
                    $temp_string = $this->suffix;
                    $temp_string = str_replace('{SNI}', $this->shortenSni("{$tmp->sni}"), $temp_string);
                    $title = trim("{$title}{$temp_string}");
                }
                if ($this->prefix !== '') {
                    $temp_string = $this->prefix;
                    $temp_string = str_replace('{SNI}', $this->shortenSni("{$tmp->sni}"), $temp_string);
                    $title = trim("{$temp_string}{$title}");
                }
                $tmp->title=$title;

                if ($this->format === 'singbox') {
                    $tmp->u = json_encode($tmp->oo, JSON_INVALID_UTF8_IGNORE);
                    $key = $this->substituteJsonMacros($tmp);
                    $o_temp = json_decode($tmp->u);
                    $o_temp->tag = $title;
                    $this->resultLines[$key] = $o_temp;
                    unset($o_temp);
                } elseif ($this->format === 'ss') {
                    $tmp->u = json_encode($tmp->ss, JSON_INVALID_UTF8_IGNORE);
                    $key = $this->substituteJsonMacros($tmp);
                    $o_temp = json_decode($tmp->u);
                    $this->resultLines[$key] = $o_temp;
                    unset($o_temp);
                } else {
                    if ($tmp->type === 'vmess') {
                        $key = $this->substituteJsonMacros($tmp);
                        $tmp->u = sprintf("vmess://%s", base64_encode($tmp->u));
                    } else {
                        $tmp->u = str_replace('{HOST}', $tmp->host, $tmp->u);
                        $tmp->u = str_replace('{SNI}', rawurlencode(@"{$tmp->sni}"), $tmp->u);
                        $tmp->u = str_replace('{FP}', rawurlencode($this->fingerprint), $tmp->u);
                        $key = md5($tmp->u);
                        $tmp->u = str_replace('{TITLE}', rawurlencode($title), $tmp->u);
                    }
                    $this->resultLines[$key] = $tmp->u;
                }
                $count++;
                if($this->limit>0 && $count>=$this->limit)
                    break;
            }
        }

//        var_dump($fmt);

        switch ($this->format) {
            case 'b64':
                echo base64_encode(implode("\n", array_values($this->resultLines)));
                break;
            case 'singbox':
                $conf = self::createSingBoxProfile($this->resultLines, $this->singbox_template, $this->singbox_dns);
                $singbox_interval = 6;
                $this->singbox_title = base64_encode($this->singbox_title);
                echo "//profile-title: base64:$this->singbox_title\n";
                echo "//profile-update-interval: {$singbox_interval}\n";
                echo "//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n";
                echo "//support-url: https://t.me/dimzon541\n";
                echo "//profile-web-page-url: https://github.com/dimzon/scaling-sniffle\n";
                echo "\n";
                echo json_encode($conf, JSON_PRETTY_PRINT + JSON_INVALID_UTF8_IGNORE);
                break;
            case 'ss':
                echo json_encode(array_values($this->resultLines), JSON_PRETTY_PRINT + JSON_INVALID_UTF8_IGNORE);
                break;
            case '':
            case 'default':
                foreach ($this->resultLines as $key => $line)
                    echo "{$line}\n";
                break;
        }
    }

    private function hostByName($str)
    {
        static $dnsCache;
        if (!is_array($dnsCache)) $dnsCache = [];
        $v = @$this->dnsCache[$str];
        if (is_string($v)) return $v;
        $v = gethostbyname($str);
        $this->dnsCache[$str] = $v;
        return $v;
    }

    private static function fcache($url)
    {
        $prefix = 'https://raw.githubusercontent.com/dimzon/scaling-sniffle/main/';
        // use local files for debug
        if (PHP_OS_FAMILY === 'Windows') $prefix = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'subs' . DIRECTORY_SEPARATOR;

        if (substr($url, -3) === '.gz')
            return @gzfile("{$prefix}{$url}");
        else
            return @file("{$prefix}{$url}");
//        $name= __DIR__ . DIRECTORY_SEPARATOR . md5($url);
//        if(!file_exists($name)){
//            $fp=fopen($name,"w");
//            flock($fp,LOCK_EX);
//            self::downloadFile($url,$fp);
//            fclose($fp);
//        }
//        $lines=[];
//        $fp=fopen($name,'rt');
//        flock($fp,LOCK_SH);
//        while (true){
//            $str=fgets($fp);
//            if($str===false) break;
//            $lines[]=$str;
//        }
//        fclose($fp);
//        return $lines;
    }

    private static function checkFlag3($flag, $value)
    {
        if (is_null($flag)) return true;
        return $flag === $value;
    }

    private static function randomItem(&$items, $seed)
    {
        $count = count($items);
        if ($count === 1) return $items[0];
        return $items[crc32($seed) % $count];
    }

    private static function randomCfHost($str)
    {
        static $ips;
        if (!is_array($ips)) {
            $f = self::fcache('cf-ip.json.gz');
            $ips = json_decode(implode("\n", $f));
        }
        return self::randomItem($ips, $str);
    }

    private static function randomGcHost($str)
    {
        static $ips;
        if (!is_array($ips)) {
            $f = self::fcache('gcore-ip.json.gz');
            $ips = json_decode(implode("\n", $f));
        }
        return self::randomItem($ips, $str);
    }

    private static function mangle($str, $seed)
    {
        $h = str_pad(decbin(crc32("{$str}\n{$seed}")), 32, '0', STR_PAD_LEFT);
        $str = str_split(strtolower($str));
        for ($i = count($str) - 1; $i >= 0; $i--)
            if ((ord($h[$i % 32]) % 2) === 0) $str[$i] = strtoupper($str[$i]);

        return implode('', $str);
    }

    private function shortenSni($sni)
    {
        if (isset($this->_shortenSni[$sni])) return $this->_shortenSni[$sni];
        $sni1 = preg_replace('/^(.*\.)?([\w\-]+\.\w+)$/m', '$2', $sni);
        $this->_shortenSni[$sni] = $sni1;
        return $sni1;
    }

    private function substituteJsonMacros($tmp): string
    {
        $tmp->u = str_replace(json_encode('{HOST}'), json_encode($tmp->host), $tmp->u);
        $tmp->u = str_replace(json_encode('{SNI}'), json_encode(@"{$tmp->sni}"), $tmp->u);
        $tmp->u = str_replace(json_encode('{FP}'), json_encode($this->fingerprint), $tmp->u);
        $key = md5($tmp->u);
        $tmp->u = str_replace(json_encode('{TITLE}'), json_encode($tmp->title), $tmp->u);
        return $key;
    }

    private static function createSingBoxProfile(&$proxies, $templateName = 'default', $dns = 'tcp://1.1.1.1')
    {
        $templateName = preg_replace('/[^\w\-]/', '', $templateName);
        $template = self::fcache("singbox-template-{$templateName}.json");
        if ($template === false) return (object)[];
        $conf = json_decode(implode("\n", $template));
        $template = json_encode($conf);
        $template = str_replace(json_encode("{DNS}"), json_encode($dns), $template);
        $conf = json_decode($template);
        $acceptors = array_filter($conf->outbounds, function ($i) {
            return false !== stripos(';selector;urltest;', @";{$i->type};");
        });
        foreach ($proxies as $proxy) {
            foreach ($acceptors as $acceptor)
                $acceptor->outbounds[] = $proxy->tag;
            $conf->outbounds[] = $proxy;
        }
        return $conf;
    }
}


