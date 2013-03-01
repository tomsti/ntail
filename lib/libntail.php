<?php

function split_ipfw_words($logbuffer) 
{
  $res = array();
  // pattern to match all ipfw syslog msg
  $pattern = "@(.*) (.*:.*:.*) (<.*\..*>) (.*) (kernel:) (ipfw:) (.*) (Deny|Allow) (TCP|UDP|ICMP) (.*:.*) (.*:.*) (in|out) (.*) (.*)@i";
  preg_match($pattern,$logbuffer,$matches);
  if(!empty($matches)) 
  {
    $res['time'] = $matches[1]." ".$matches[2];
    $res['pri'] = $matches[3];
    $res['host'] = substr($matches[4],0,8);
    $res['level'] = $matches[5];
    $res['app'] = $matches[6];
    $res['rulenum'] = $matches[7];
    $res['action'] = $matches[8];
    $res['protocol'] = $matches[9];
    $ips = explode(":",$matches[10]);
    $res['ip_from'] = $ips[0];
    $res['port_from'] = $ips[1];
    $ipd = explode(":",$matches[11]);
    $res['ip_to'] = $ipd[0];
    $res['port_to'] = $ipd[1];
    $res['direction'] = $matches[12]." ".$matches[13];
    $res['ifconf'] = $matches[14];
    return $res;
  }
  return FALSE;
}

function split_nginx_words($logbuffer)
{
	$res = array();
	// pattern to match all ipfw syslog msg
	//IP - - [DATETIME] "GET|POST|PUT UR HTTP/1.1" CODE BYTES "HOST" "USER-AGENT" "REF"
	//50.150.127.59 - - [28/Feb/2013:23:23:13 -0800] "GET /json/top_country_attacks/since/1362122531 HTTP/1.1" 200 631 "http://www.norse-corp.com/" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17" "-"
	preg_match('@^(.*) \- \- \[(.+?)\] "(.*?) (.*?) (.*?)" ([0-9]+) ([0-9]+) "(.*?)" "(.*?)" "(.*?)"@i', $logbuffer, $matches);
	//var_dump($matches);
	if(!empty($matches))	{
		$res['time'] = $matches[2];
		$res['verb'] = $matches[3];
		$res['ip'] = $matches[1];
		$res['domain'] = $matches[8];
		$res['uri'] = $matches[4];
		return $res;
	}
	return FALSE;
}

function ipviking_api_call($log)
{
  global $conf;
  
  if($conf['type']=="ipfw")
	  $ip_from = $log['ip_from'];
  elseif($conf['type']=="nginx")
  	  $ip_from = $log['ip'];
  
  if(ip_is_private($ip_from)) {
  	$log['ip_from_ipq'] = 0;
  	$log['ip_from_cc'] = "-";
  	$log['ip_from_city'] ='-';
  	$log['ip_from_org'] ='-';
  	$log['categories'] = '';
  	return $log;
  }
  $memcache = memcache_pconnect($conf['memcached_host'], $conf['memcached_port']);
  
  $categories = ''; $x=0;

  $ip_from_md5 = md5($ip_from);
  $var = memcache_get($memcache, $ip_from_md5);
  if($var!==FALSE) 
  {
    if(is_object($var)) {
      $IPViking_json = $var;
      $IPViking_http_code=302;
      if($IPViking_json->response->geoloc->country=="-" || $IPViking_json->response->geoloc->organization=="-") 
      {
        $IPViking_http_code=0;
        $IPViking_json='';
      }
    } else {
      $IPViking_json = '';
      $IPViking_http_code=$var;
      $IPViking_http_code_msg='';
    }
  }
  if(empty($IPViking_json)) 
  {
    $requestdata = array('apikey' => $conf['APIKEY'],'method' => 'ipq','ip' => $ip_from);
    $IPViking = new IPvikingRequest($conf['APIURL'], "POST",$requestdata);
    $IPViking->execute();
    $IPViking_header = $IPViking->getResponseInfo();
    $IPViking_body = $IPViking->getResponseBody();
    $IPViking_http_code = $IPViking_header['http_code'];
    $IPViking_json = json_decode($IPViking_body);
    if($IPViking_http_code==302) memcache_add($memcache, $ip_from_md5, $IPViking_json, false, 3600*8);
    else memcache_add($memcache, $ip_from_md5, -1, false, 3600*2);
    $IPViking_http_code_msg = $IPViking->getStatusCodeMessage($IPViking_http_code);
  }
  if($IPViking_http_code==302) 
  {
        $log['ip_from_ipq']=round($IPViking_json->response->risk_factor);
        $log['ip_from_cc'] = substr($IPViking_json->response->geoloc->country,0,20);
        $log['ip_from_city'] = substr($IPViking_json->response->geoloc->city,0,26);
        $log['ip_from_org'] = substr($IPViking_json->response->geoloc->organization,0,26);
        if(isset($IPViking_json->response->entries)) {
          foreach($IPViking_json->response->entries AS $entries) 
          {
                $categories = $entries->category_name;
                $x++;
          }
          $log['categories'] = $categories." ($x)";
        } else $log['categories'] = '';
  } else {
      // ERROR return
      $log['ip_from_ipq'] = $IPViking_http_code;
      $log['ip_from_cc'] = substr($IPViking_http_code_msg,0,20);
      $log['ip_from_city'] ='-';
      $log['ip_from_org'] ='-';
      $log['categories'] = '';
  }
  return($log);
}
function color_log_strings($log)
{
	global $conf;
  // timestamp
  if($log['time']) $log['time']="\033[1;37m\033[44m".$log['time']."\033[0m";
  
  // IPQ score
  if($log['ip_from_ipq']>=80) $log['ip_from_ipq']="\033[1;31m".$log['ip_from_ipq']."\033[1;39m";
  elseif($log['ip_from_ipq']>=60) $log['ip_from_ipq']="\033[1;31m".$log['ip_from_ipq']."\033[1;39m";
  elseif($log['ip_from_ipq']>=30) $log['ip_from_ipq']="\033[1;33m".$log['ip_from_ipq']."\033[1;39m";
  elseif($log['ip_from_ipq']>=1) $log['ip_from_ipq']="\033[1;32m".$log['ip_from_ipq']."\033[1;39m";
  else $log['ip_from_ipq']="\033[1;37m".$log['ip_from_ipq']."\033[1;39m";
    
  // company name
  if($log['ip_from_cc']=="United States") {
    if($log['ip_from_org']) 
      $log['ip_from_org']="\033[1;33m".$log['ip_from_org']."\033[1;39m";
  } else {
    if($log['ip_from_org']) $log['ip_from_org']="\033[1;37m".$log['ip_from_org']."\033[1;39m";
  }
  
  if($conf['type']=="ipfw") {
	  // ip_from
	  if($log['ip_from']) $log['ip_from']="\033[1;34m".$log['ip_from']."\033[1;39m";    
	  if($log['port_from']) $log['port_from']="\033[1;35m".$log['port_from']."\033[1;39m";
	  // ip_to
	  if($log['ip_to']) $log['ip_to']="\033[1;35m".$log['ip_to']."\033[1;39m";
	  if($log['port_to']) $log['port_to']="\033[1;34m".$log['port_to']."\033[1;39m";
  }
  if($conf['type']=="nginx") {
  	if($log['ip']) $log['ip']="\033[1;34m".$log['ip']."\033[1;39m";
  }
  return($log);
}
function display_logline($log)
{
  global $conf;
  
  if($conf['type']=="ipfw") {
	  //echo $log['time']." ";                                                //
	  echo str_pad($log['host'],8)." ";                                       // substr(10)
	  echo str_pad($log['ip_from_ipq'],20," ",STR_PAD_LEFT)." ";              // 6
	  echo str_pad($log['ip_from_cc'],20)." ";                                // 
	  echo str_pad($log['ip_from_org'],40)." ";								  //
	  echo str_pad($log['protocol'],4)." ";									  //
	  echo "".str_pad($log['ip_from'].":".$log['port_from'],48)." ";
	  echo "> ";
	  echo "".str_pad($log['ip_to'].":".$log['port_to'],48)." ";
  }
  if($conf['type']=="nginx") {
  	echo "".str_pad($log['ip'],30)." ";
  	echo str_pad($log['ip_from_ipq'],20," ",STR_PAD_LEFT)." ";
  	echo str_pad($log['ip_from_cc'],20)." ";
  	echo str_pad($log['ip_from_org'],40)." ";
  	echo str_pad($log['verb'],4)." ";
  	echo str_pad($log['uri'],50)." ";  	
  }
  echo $log['categories']."";
  echo "\n";
}

function ip_is_private ($ip) {
	$pri_addrs = array (
			'10.0.0.0|10.255.255.255', // single class A network
			'172.16.0.0|172.31.255.255', // 16 contiguous class B network
			'192.168.0.0|192.168.255.255', // 256 contiguous class C network
			'169.254.0.0|169.254.255.255', // Link-local address also refered to as Automatic Private IP Addressing
			'127.0.0.0|127.255.255.255' // localhost
	);

	$long_ip = ip2long ($ip);
	if ($long_ip != -1) {

		foreach ($pri_addrs AS $pri_addr) {
			list ($start, $end) = explode('|', $pri_addr);

			// IF IS PRIVATE
			if ($long_ip >= ip2long ($start) && $long_ip <= ip2long ($end)) {
				return true;
			}
		}
	}

	return false;
}
?>