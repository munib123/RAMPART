# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 876_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `876_6`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php

	 $interval = 2;	
		
    $tx_path = 'cat /sys/class/net/eth0/statistics/tx_bytes';
    $rx_path = 'cat /sys/class/net/eth0/statistics/rx_bytes';

    $tx_start = intval(shell_exec($tx_path));
    $rx_start = intval(shell_exec($rx_path));

    sleep($interval);

    $tx_end = intval(shell_exec($tx_path));
    $rx_end = intval(shell_exec($rx_path));

    $result['tx'] = round(($tx_end - $tx_start)/1024, 2);
    $result['rx'] = round(($rx_end - $rx_start)/1024, 2);
    
    //echo json_encode($result);
	 echo "TX: ".$result['tx']." KB/s<br>";    
    echo "RX: ".$result['rx']." KB/s";
    
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,7 @@
 <?php
+
+Session::checkLoginUser();
+Session::checkRight("profile", READ);
 
 	 $interval = 2;	
 		
```
