<?php
class Wg2Hidify{
    private $_a;
    private $_ini;
    public function __construct($_a)
    {
        $this->_a = $_a;
        if($this->source()==='') return;
        $str=parse_ini_string($this->source(),true,INI_SCANNER_RAW);
        $this->lowerCaseArrayRecursive($str);
        $str=json_decode(json_encode($str));
        $this->_ini=$str;
//        var_dump(json_encode($str));
    }


    public function createConfig(){
        return (object)[
            'log' => [
                'level' => 'warn',
                'output' => 'box.log',
                'timestamp' => true,
            ],
            'dns' => [
                'servers' => [
                    [
                        'tag' => 'dns-remote',
                        'address' => $this->dnsServer(),
                        'address_resolver' => 'dns-direct',
                        'strategy' => 'prefer_ipv4',
                    ],
                    [
                        'tag' => 'dns-trick-direct',
                        'address' => 'https://sky.rethinkdns.com/',
                        'strategy' => 'prefer_ipv4',
                        'detour' => 'direct-fragment',
                    ],
                    [
                        'tag' => 'dns-direct',
                        'address' => '1.1.1.1',
                        'address_resolver' => 'dns-local',
                        'strategy' => 'prefer_ipv4',
                        'detour' => 'direct',
                    ],
                    [
                        'tag' => 'dns-local',
                        'address' => 'local',
                        'detour' => 'direct',
                    ],
                    [
                        'tag' => 'dns-block',
                        'address' => 'rcode://success',
                    ],
                ],
                'rules' => [
                    [
                        'domain' => 'cp.cloudflare.com',
                        'server' => 'dns-remote',
                        'rewrite_ttl' => 3000,
                    ],
                ],
                'final' => 'dns-remote',
                'static_ips' => [
                    'sky.rethinkdns.com' => [
                        '188.114.97.1',
                        '2a06:98c1:3120::1',
                        '2a06:98c1:3121::1',
                        '188.114.96.1',
                        '104.18.202.232',
                        '104.18.203.232',
                        '172.64.172.4',
                        '172.64.173.4',
                        '2606:4700:e4::ac40:ad04',
                        '2606:4700:e4::ac40:ac04',
                    ],
                ],
                'independent_cache' => true,
            ],
            'inbounds' => [
                [
                    'type' => 'tun',
                    'tag' => 'tun-in',
                    'mtu' => 9000,
                    'inet4_address' => '172.19.0.1/28',
                    'inet6_address' => 'fdfe:dcba:9876::1/126',
                    'auto_route' => true,
                    'strict_route' => true,
                    'endpoint_independent_nat' => true,
                    'sniff' => true,
                    'sniff_override_destination' => true,
                    'domain_strategy' => 'prefer_ipv4',
                ],
                [
                    'type' => 'mixed',
                    'tag' => 'mixed-in',
                    'listen' => '127.0.0.1',
                    'listen_port' => 2334,
                    'sniff' => true,
                    'sniff_override_destination' => true,
                    'domain_strategy' => 'prefer_ipv4',
                ],
                [
                    'type' => 'direct',
                    'tag' => 'dns-in',
                    'listen' => '127.0.0.1',
                    'listen_port' => 6450,
                    'override_address' => '1.1.1.1',
                    'override_port' => 53,
                ],
            ],
            'outbounds' => [
                [
                    'type' => 'selector',
                    'tag' => 'select',
                    'outbounds' => [
                        'auto',
                        $this->proxyName(),
                    ],
                    'default' => 'auto',
                ],
                [
                    'type' => 'urltest',
                    'tag' => 'auto',
                    'outbounds' => [
                        $this->proxyName(),
                    ],
                    'url' => 'https://8.8.8.8/generate_204',
                    'interval' => '15m0s',
                ],
                [
                    'type' => 'wireguard',
                    'tag' => $this->proxyName(),
                    'local_address' => $this->localAddress(),
                    'private_key' => @"{$this->_ini->interface->privatekey}",
                    'server' => $this->server(),
                    'server_port' => $this->serverPort(),
                    'peer_public_key' => @"{$this->_ini->peer->publickey}",
                    'mtu' => $this->mtu(),
                    'fake_packets' => $this->fakePackets(),
                    'fake_packets_size' => '40-100',
                    'fake_packets_delay' => '10-200',
                ],
                [
                    'type' => 'dns',
                    'tag' => 'dns-out',
                ],
                [
                    'type' => 'direct',
                    'tag' => 'direct',
                ],
                [
                    'type' => 'direct',
                    'tag' => 'direct-fragment',
                    'tls_fragment' => [
                        'enabled' => true,
                        'size' => '1-500',
                        'sleep' => '0-500',
                    ],
                ],
                [
                    'type' => 'direct',
                    'tag' => 'bypass',
                ],
                [
                    'type' => 'block',
                    'tag' => 'block',
                ],
            ],
            'route' => [
                'geoip' => [
                    'path' => 'geo-assets/sagernet-sing-geoip-geoip.db',
                ],
                'geosite' => [
                    'path' => 'geo-assets/sagernet-sing-geosite-geosite.db',
                ],
                'rules' => [
                    [
                        'inbound' => 'dns-in',
                        'outbound' => 'dns-out',
                    ],
                    [
                        'port' => 53,
                        'outbound' => 'dns-out',
                    ],
                    [
                        'clash_mode' => 'Direct',
                        'outbound' => 'direct',
                    ],
                    [
                        'clash_mode' => 'Global',
                        'outbound' => 'select',
                    ],
                    [
                        'geoip' => 'private',
                        'outbound' => 'bypass',
                    ]
                ],
                'final' => 'select',
                'auto_detect_interface' => true,
                'override_android_vpn' => true,
            ],
            'experimental' => [
                'cache_file' => [
                    'enabled' => true,
                    'path' => 'clash.db',
                ],
                'clash_api' => [
                    'external_controller' => '127.0.0.1:6756',
                ],
            ],
        ];
    }

    public function resolve(){
        return @"{$this->_a['ipify']}"!='';
    }
    public function source(){
        return trim(@"{$this->_a['source']}");
    }
    public function json(){
        if($this->source()==='') return '';
        return json_encode($this->createConfig(), JSON_PRETTY_PRINT);
    }

    private function lowerCaseArrayRecursive(&$str)
    {
        $str=array_change_key_case($str);
        foreach ($str as &$inner)
            if(is_array($inner))
                $this->lowerCaseArrayRecursive($inner);
    }

    private function localAddress(){
        return array_map(function ($a){
            $a=trim($a);
            if(strpos($a,'/')) return $a;
            if(false!==filter_var($a,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))
                return "$a/32";
            else
                return "$a/128";
        }, explode(',', @"{$this->_ini->interface->address}"));
    }

    private function serverPort()
    {
        return parse_url(@"http://{$this->_ini->peer->endpoint}/",PHP_URL_PORT);
    }
    private function server()
    {
        $host = parse_url(@"http://{$this->_ini->peer->endpoint}/", PHP_URL_HOST);
        if($this->resolve())
            $host=gethostbyname($host);
        return $host;
    }

    private function dnsServer()
    {
        $dns=trim(@"{$this->_ini->interface->dns}");
        $dns=trim(explode(',',$dns)[0]);
        if($dns==='') return 'https://1.1.1.1/dns-query';
        return $dns;
    }

    private function proxyName()
    {
        return 'wg-conf';
    }

    private function mtu()
    {
        $mtu=intval(@"{$this->_ini->interface->mtu}");
        if($mtu<=0) $mtu=1280;
        return $mtu;
    }

    private function fakePackets()
    {
        return "7-20";
    }
}

$o=new Wg2Hidify($_POST);
?><!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" />
    <style>
        *{background-color: khaki;color: #000000;font-family: monospace;}
        div{padding: 4px;}
        textarea{background-color: white;}
        button{ padding: 8px; border: 0;  background-color: #0969da;color: #ffffff;font-weight: bold;}
    </style>
    <script type="text/javascript">
        function copy(){
            navigator.clipboard.writeText(document.getElementById('txtResult').value);
        }
    </script>
    <title>wireguard 2 hidify</title>
</head><body>
<form method="post">
    <div>wg.conf:</div>
    <div>
        <textarea cols="80" rows="10" name="source"><?php echo htmlspecialchars($o->source())?></textarea>
    </div>
    <div>
        <label><input type="checkbox" <?php echo $o->resolve()?"checked":"";?> name="ipify">resolve endpoint address</label>
    </div>
    <div>
        <button type="submit">Convert</button>
    </div>

</form>
<div>Output:</div>
<div>
    <textarea id="txtResult" readonly cols="80" rows="20"><?php echo htmlspecialchars($o->json())?></textarea>
</div>
<div>
    <button onclick="copy()">Copy to clipboard</button>
</div>
</body></html>

