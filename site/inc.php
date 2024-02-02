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
    private static function fillSni($i, &$tmp){
        switch (strtolower($i)) {
            case 'mts-sn':
                self::fillSni('mts-ok',$tmp);
                break;
            case 'mts-im':
                self::fillSni('mts-viber',$tmp);
                self::fillSni('mts-telegram',$tmp);
                self::fillSni('mts-skype',$tmp);
                self::fillSni('mts-whatsapp',$tmp);
                self::fillSni('mts-snapchat',$tmp);
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

    public static function execute()
    {
        $suffix = rtrim(@"{$_GET['suffix']}");
        $prefix = ltrim(@"{$_GET['prefix']}");

        $cfhost = self::arrayValue('cf-server');
        if (false === $cfhost)
            $cfhost = ['speed.cloudflare.com'];
        $gchost = self::arrayValue('gc-server');
        if (false === $gchost)
            $gchost = ['gcore.com'];

        $resultLines = [];
        $b64 = self::boolFlag('b64');

        $fp = trim(@"{$_GET['fp']}");
        if ($fp === '') $fp = 'chrome';
        $fsni = self::arrayValue('sni');
        $sni = '';
        if (is_array($fsni)) {
            $tmp=[];
            foreach ($fsni as $i) self::fillSni($i,$tmp);
            $fsni=$tmp;
            unset($tmp);
            unset($i);

            $sni = @"{$fsni[0]}";
            $fsni = array_map(function ($x) {
                return preg_quote($x);
            }, $fsni);
            $fsni = '/^(?:.*\.)?(?:' . implode('|', $fsni) . ')$/mi';
        }
        if ($sni === '') $sni = 'vkvd127.mycdn.me';


        $mangle = @"{$_GET['mangle']}";

        $full = self::boolFlag('full');

        $cdnfilter = [];
        if (self::boolFlag('cf')) $cdnfilter['cf'] = true;
        if (self::boolFlag('gc')) $cdnfilter['gcore'] = true;


        $tag = strtolower(trim(@"{$_GET['tag']}"));
        if ('' === $tag) $tag = 'freedom';
//        $tag = "f_{$tag}";

        $ipfy = self::boolFlag('ipfy');

        $fvision = self::boolFlag('vision');

        if (false !== $cfhost && $ipfy === true)
            foreach ($cfhost as &$item)
                $item = self::hostByName($item);

        $fgeo = self::stringFilter('country', '/[^A-Z]+/i');

        $fkind = self::stringFilter('kind', '/[^a-z0-9_]+/');
        if (false !== $fkind && false !== stripos($fkind, ';ss;'))
            $fkind = "{$fkind}shadowsocks;ss2022;ss_legacy;";

        $fsec = self::stringFilter('security', '/[^a-z]+/');
        if (false !== $fsec && false !== stripos($fsec, ';tls;'))
            $fsec = "{$fsec}reality;";

        $fnet = self::stringFilter('network', '/[^a-z2]+/');

        $fport = self::stringFilter('port', '/[^0-9]+/');


        if (false === $full)
            $template="proxy-db-{$tag}.lst";
        else
            $template='proxy-db.lst';


        $template = "https://raw.githubusercontent.com/dimzon/scaling-sniffle/main/{$template}.gz";
        $lines = self::fcache($template);
        if (is_array($lines)) {
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '') continue;
                if (0 === strpos($line, '#')) continue;
                $tmp = json_decode($line);
                if (!is_object($tmp)) continue;

                if ($fvision === true && (!isset($tmp->vision) || $tmp->vision == false))
                    continue;
//                var_dump(1);

                if (count($cdnfilter)!==0)
                    if (!isset($cdnfilter[$tmp->k]))
                        continue;
//                var_dump(2);

//                if (false === $full)
//                    if (!isset($tmp->{$tag}) || $tmp->{$tag} !== true)
//                        continue;
//                var_dump(3);

                if (false !== $fkind)
                    if (false === stripos($fkind, ";{$tmp->type};"))
                        continue;
//                var_dump(4);

                if (false !== $fgeo)
                    if (false === stripos($fgeo, ";{$tmp->cc};"))
                        continue;
//                var_dump(5);

                if (false !== $fnet)
                    if (false === stripos($fnet, ";{$tmp->net};"))
                        continue;
//                var_dump(6);

                if (false !== $fport)
                    if (false === strpos($fport, ";{$tmp->port};"))
                        continue;
//                var_dump(7);

                if (false !== $fsec)
                    if (false === stripos($fsec, ";{$tmp->sec};"))
                        continue;
//                var_dump(8);



                $sniOk = $fsni === false;
                if ($tmp->k === 'sni') {
                    $sniOk = true;
                    $tmp->sni = $sni;
                } elseif ($fsni !== false && preg_match($fsni, @"{$tmp->sni}"))
                    $sniOk = true;


                if ($sniOk === false)
                    continue;
//                var_dump(9);

                if ($tmp->k === 'cf') {
                    $h = self::randomItem($cfhost, "{$tmp->sni}|{$tmp->u}");
                    if (0 === stripos($h, 'rand:'))
                        $h = self::randomCfHost("{$tmp->sni}|{$tmp->u}|{$h}");
                    $tmp->host = $h;
                } elseif ($tmp->k === 'gcore') {
                    $h = self::randomItem($gchost, "{$tmp->sni}|{$tmp->u}");
                    if (0 === stripos($h, 'rand:'))
                        $h = self::randomGcHost("{$tmp->sni}|{$tmp->u}|{$h}");
                    $tmp->host = $h;
                } elseif ($ipfy) {
                    $tmp->host = self::hostByName($tmp->host);
                }

                if ($fsni === false && strlen($mangle) !== 0 && @"{$tmp->sni}" !== '') {
                    $tmp->sni = self::mangle(@"{$tmp->sni}", $mangle);
                }

                $title=$tmp->t;
                if($suffix!==''){
                    $temp_string=$suffix;
                    $temp_string=str_replace('{SNI}', self::shortenSni("{$tmp->sni}"), $temp_string);
                    $title=trim("{$title}{$temp_string}");
                }
                if($prefix!==''){
                    $temp_string=$prefix;
                    $temp_string=str_replace('{SNI}', self::shortenSni("{$tmp->sni}"), $temp_string);
                    $title=trim("{$temp_string}{$title}");
                }

                if ($tmp->type === 'vmess') {
                    $tmp->u = str_replace(json_encode('{HOST}'), json_encode($tmp->host), $tmp->u);
                    $tmp->u = str_replace(json_encode('{SNI}'), json_encode(@"{$tmp->sni}"), $tmp->u);
                    $tmp->u = str_replace(json_encode('{FP}'), json_encode($fp), $tmp->u);
                    $key = md5($tmp->u);
                    $tmp->u = str_replace(json_encode('{TITLE}'), json_encode($title), $tmp->u);
                    $tmp->u = sprintf("vmess://%s", base64_encode($tmp->u));
                } else {
                    $tmp->u = str_replace('{HOST}', $tmp->host, $tmp->u);
                    $tmp->u = str_replace('{SNI}', rawurlencode(@"{$tmp->sni}"), $tmp->u);
                    $tmp->u = str_replace('{FP}', rawurlencode($fp), $tmp->u);
                    $key = md5($tmp->u);
                    $tmp->u = str_replace('{TITLE}', rawurlencode($title), $tmp->u);
                }

                $resultLines[$key] = $tmp->u;
            }
        }
        if ($b64) {
            echo base64_encode(implode("\n", array_values($resultLines)));
        } else {
            foreach ($resultLines as $key => $line)
                echo "{$line}\n";
        }
    }

    private static $_shortenSni;
    private static function shortenSni($sni){
        if(!is_array(self::$_shortenSni)) self::$_shortenSni=[];
        if(isset(self::$_shortenSni[$sni])) return self::$_shortenSni[$sni];
        $sni1=preg_replace('/^(.*\.)?([\w\-]+\.\w+)$/m','$2',$sni);
        self::$_shortenSni[$sni]=$sni1;
        return $sni1;
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

    private static function hostByName($str)
    {
        static $ca;
        if (!is_array($ca)) $ca = [];
        $v = @$ca[$str];
        if (is_string($v)) return $v;
        $v = gethostbyname($str);
        $ca[$str] = $v;
        return $v;
    }

    private static function stringFilter($name, $regex)
    {
        $lst = trim(preg_replace($regex, ';', @"{$_GET[$name]}"), ';');
        return $lst === ''
            ? false
            : strtolower(";{$lst};");
    }

    private static function fcache($url)
    {
        return gzfile($url);
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
            $f = self::fcache('https://raw.githubusercontent.com/dimzon/scaling-sniffle/main/cf-ip.json.gz');
            $ips = json_decode(implode("\n", $f));
        }
        return self::randomItem($ips, $str);
    }

    private static function randomGcHost($str)
    {
        static $ips;
        if (!is_array($ips)) {
            $f = self::fcache('https://raw.githubusercontent.com/dimzon/scaling-sniffle/main/gcore-ip.json.gz');
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

//    private static function listFilter($name, $map)
//    {
//        $lst = trim(@"{$_GET[$name]}");
//        if ($lst === '') return false;
//
//        $lst = array_map($map, array_filter(preg_split('/[^A-Z]+/', $lst), function ($i) {
//            return $i !== '';
//        }));
//        if (0 == count($lst))
//            return false;
//        return $lst;
//    }
//
//    private static function downloadFile($url, $fp)
//    {
//        $data = gzdecode(file_get_contents($url));
//        fwrite($fp, $data);
//    }
}


