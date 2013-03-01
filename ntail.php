#!/usr/local/bin/php
<?php

// parse conf file into conf
// scan more dirs later for conf file
$conf = array();				// conf file settings
$conf = parse_ini_file("/usr/local/etc/ntail.conf");

if($conf['debug'])
	error_reporting(E_ALL);			// debug settings
else 
	error_reporting(0);			// debug settings

$filter = FALSE;
$missing_f = TRUE;
$help=FALSE;
$do_color = TRUE;				// default pretty
$do_ipviking = TRUE;			// default API lookup
$filename = '';
$type='ipfw';					// default type

$options = getopt("f:t:hci");
if(isset($options['h']))  $help = TRUE;
if(isset($options['c'])) $do_color = FALSE;
if(isset($options['i'])) $do_ipviking = FALSE;
if(isset($options['f']) AND $options['f']!="") {
        $filename = $options['f'];
        if(!file_exists($filename)) {
                echo "$filename does not exists\n";
                exit(0);
        } else $missing_f=FALSE;
        
} else {
        $help=TRUE;
        $missing_f=TRUE;
        echo "Missing mandatory -f <filename>\n";
}

if(isset($options['t']) AND $options['t']!="") {
        $type = $options['t'];
} 

if(isset($options['g']) AND $options['g']!="") {
        $pattern = $options['g'];
        $filter = TRUE;
} 
if($help || $missing_f) {
        print("\t\tIPViking API tail like log watcher!\n\n
                Integrate intelligence into log files, and supports
                many log formats like ipfw syslog output\n\n
                Command: ntail -f <filename> -t <type> [default to ipfw]
                \t-f <filename>\t\tLogfile filename to tail\n
                \t-t <type>\t\tLog Types supported nginx ipfw
                \t-h           \t\tThis help\n
                \t-c           \t\tskip coloring\n
                \t-i           \t\tskip IPviking API call\n
        		\t-g [expression] \tFilter out expression\n
                So enjoy, please feedback this way ts@norse-cop.com\n
                http://norse-corp.com 
                http://ipviking.com\n\n");
        exit(0);
}

//include ipviking API
include("/usr/local/lib/ipviking/libipviking.php");
//ntail libs
include("/usr/local/lib/ipviking/libntail.php");

// supplement conf
$conf['type'] = $type;

$handle = popen("tail -F ".$filename." 2>&1", 'r');
while(!feof($handle)) 
{
    $buffer = fgets($handle);
    if($filter) {
    	if(strpos($buffer,$pattern))
    		continue;
    }
    if($type=="ipfw")
	    $logarray = split_ipfw_words($buffer);
    elseif($type=="nginx")
    	$logarray = split_nginx_words($buffer);
    else {
    	echo "\nError: Unsupported filetype format '$type'\n\n";
    	echo "\nuse ntail -h for help\n\n";
    	exit(0);
    }
    	
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