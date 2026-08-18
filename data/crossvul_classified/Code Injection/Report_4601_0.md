# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 4601_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4601_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 5-45 of the vulnerable file.

<style>
@import "Base.css";
</style>
</head>

<body>
<script type="text/javascript" src="PS_Info.js" ></script>
<script type="text/javascript" src="Fan_Info.js" ></script>
<script type="text/javascript" src="Temp_Info.js" ></script>
<script type="text/javascript" src="Storage_Info.js" ></script>
<script type="text/javascript" src="Memory_Info.js" ></script>
<script type="text/javascript" src="CPU_Info.js" ></script>
<script type="text/javascript" src="Network_Info.js" ></script>

<script language="JavaScript" type="text/javascript" >

<?php
        $ip=$_GET["ip"];
        $comm=$_GET["comm"];
        $id=$_GET["id"];
        $cmd="./nagios_hpeilo_engine -H $ip -C $comm -o $id -J";
        $ret = exec($cmd,$output);
        echo join("\n",$output);
?>

if (jData != "") {
	TableProcessing(serviceID);
}
else {
	NojsonData(serviceID);
}

function TableProcessing (value) {
    switch (value) {
    case 1:
		PS_Table();
        break;
    case 2:
		Fan_Table();
        break;
    case 3:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,7 +22,7 @@
         $ip=$_GET["ip"];
         $comm=$_GET["comm"];
         $id=$_GET["id"];
-        $cmd="./nagios_hpeilo_engine -H $ip -C $comm -o $id -J";
+        $cmd=escapeshellcmd("./nagios_hpeilo_engine -H $ip -C $comm -o $id -J");
         $ret = exec($cmd,$output);
         echo join("\n",$output);
 ?>
```
