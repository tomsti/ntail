#!/usr/local/bin/php 
<?php

error_reporting(E_ALL);
$missing_f = TRUE;
$help=FALSE;
$do_color = TRUE;
$do_ipviking = TRUE;
$filename = '';
$type='ipfw';

$options = getopt("f:t:hci");
if(isset($options['h']))  $help = TRUE;
if(isset($options['c'])) $do_color = FALSE;
if(isset($options['i'])) $do_ipviking = FALSE;
if(isset($options['f']) AND $options['f']!="") 
{
        $filename = $options['f'];
        if(!file_exists($filename)) 
        {
                echo "$filename does not exists\n";
                exit(0);
        } else $missing_f=FALSE;
} else {
        $help=TRUE;
        $missing_f=TRUE;
        echo "Missing mandatory -f <filename>\n";
}
if(isset($options['t']) AND $options['t']!="")
{
        $type = $options['t'];
        if($type!='ipfw' || $type!='apache' || $type!='auth' || $type!='nginx' || $type!='ipviking')
        {
                $type='ipfw';
        } 
} else {
        $type = 'ipfw';
}
if($help || $missing_f) 
{
        print("\t\tIPViking API tail like log watcher!\n\n
                Integrate intelligence into log files, and supports
                many log formats like ipfw syslog output\n\n
                Command: ntail -f <filename> -t <type> [default to ipfw]
                \t-f <filename>\t\tLogfile filename to tail\n
                \t-t <type>\t\tLog Types supported <ipviking> <apache> <nginx> <auth>
                \t-h           \t\tThis help\n
                \t-c           \t\tskip coloring\n
                \t-i           \t\tskip IPviking API call\n
                So enjoy, please feedback this way ts@norse-cop.com\n
                http://norse-corp.com 
                http://ipviking.com\n\n");
        exit(0);
}

//include ipviking API
include("/usr/local/lib/ipviking/libipviking.php");
//ntail libs
include("/usr/local/lib/ipviking/libntail.php");

$handle = popen("tail -F ".$filename." 2>&1", 'r');
while(!feof($handle)) 
{
    $buffer = fgets($handle);
    $logarray = split_ipfw_words($buffer);
    if($logarray === FALSE) { flush(); continue; } 
    if($do_ipviking) 
            $logarray = ipviking_api_call($logarray);
    if($do_color) 
            $logarray = color_log_strings($logarray);
    display_logline($logarray);
    flush();
}
pclose($handle);
// Nov 4 19:23:23 hostname IPQ city, cc, org (ip:port) -> city,cc protocol (ip:port) category|caterory2
//$log = "This is a log \033[31mmessage \033[1;39m";
//echo "$log\n";
?>