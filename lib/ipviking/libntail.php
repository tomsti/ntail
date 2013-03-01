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

function ipviking_api_call($log)
{
  $memcache = memcache_pconnect('10.0.0.3', 11211);
  $ip_from = $log['ip_from'];
  $ip_to = $log['ip_to'];
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
    $requestdata = array('apikey' => '2749597cbef5b9a6abfb91cd7ba4ba4e8b0341814900ebe5bc614b9366e490ab','method' => 'ipq','ip' => $ip_from);
    $IPViking = new IPvikingRequest("http://us.api.ipviking.com/api/", "POST",$requestdata);
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
  
  // ip_from
  if($log['ip_from']) $log['ip_from']="\033[1;34m".$log['ip_from']."\033[1;39m";  
  if($log['port_from']) $log['port_from']="\033[1;35m".$log['port_from']."\033[1;39m";
  
  // ip_to
  if($log['ip_to']) $log['ip_to']="\033[1;35m".$log['ip_to']."\033[1;39m";
  if($log['port_to']) $log['port_to']="\033[1;34m".$log['port_to']."\033[1;39m";
  
  return($log);
}
function display_logline($log)
{
  //array to display
  //echo $log['time']." ";                                                //
  echo str_pad($log['host'],8)." ";                                        // substr(10)
  echo str_pad($log['ip_from_ipq'],20," ",STR_PAD_LEFT)." ";                // 6
  echo str_pad($log['ip_from_cc'],20)." ";                                  // 
  //echo str_pad($log['ip_from_city'],12)." ";                                //
  echo str_pad($log['ip_from_org'],40)." ";
  echo str_pad($log['protocol'],4)." ";
  echo "".str_pad($log['ip_from'].":".$log['port_from'],48)." ";
  echo "> ";
  echo "".str_pad($log['ip_to'].":".$log['port_to'],48)." ";
  echo $log['categories']."";
  echo "\n";
  
}

?>