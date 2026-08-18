# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1486_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1486_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 86-126 of the vulnerable file.

?>
<!-- Toolbar -->
<TR>
<TD class="scms_toolbar">

	<?######### FUNCTION BAR ############?>
      <table width="100%" border="0" cellpadding="0" cellspacing="0">
        <tr> 
		  <?############ delete  ###########?>
				<TD nowrap><a href="javascript:void(avaaken('delete_log.php?tbl=error_log','366','450','log'))"><IMG SRC="<?=$site->CONF['wwwroot'].$site->CONF['styles_path']?>/gfx/icons/16x16/actions/delete.png" WIDTH="16" HEIGHT="16" BORDER="0" ALT="" align=absmiddle> <?=$site->sys_sona(array(sona => 'kustuta' , tyyp=>"editor"))?></a></TD>
		<?###### refresh button ######?>
				<TD nowrap><a href="javascript:document.forms['searchform'].submit();" class="scms_button_img"><IMG SRC="<?=$site->CONF['wwwroot'].$site->CONF['styles_path']?>/gfx/icons/16x16/actions/refresh.png" WIDTH="16" HEIGHT="16" BORDER="0" ALT="" align=absmiddle> <?=$site->sys_sona(array(sona => 'refresh' , tyyp=>"admin"))?></a></TD>

		
		<?###### wide middle cell ######?>
        <td width="100%"></td>


		<?###### search box ######?>
		<form id="searchform" name="searchform" action="<?=$site->self?>" method="GET">
	<? foreach($site->fdat as $fdat_field=>$fdat_value) { ?>
		<input type=hidden name="<?=$fdat_field?>" value="<?=$fdat_value?>">
	<? } ?>
		<input type="hidden" name="otsi" value=1>
		<input type="hidden" name="page" value=""><?# if search smth => reset page number to 1 (Bug #1697)?>

		
		<td style="padding-right: 10px">
			<? $search_str = $site->sys_sona(array(sona => "otsi", tyyp=>"editor")); ?>
	          <input name="filter" type="text" class="scms_flex_input" style="width:150px" value="<?=$site->fdat['filter']? $site->fdat['filter'] : $search_str.':'?>" onFocus="if(this.value=='<?=$search_str?>:') this.value='';" onBlur="if(this.value=='')this.value='<?=$search_str?>:';" onkeyup="javascript: if(event.keyCode==13){this.form.submit();}">

		</td>

		<?########## starting + cal ?>

        <td><?=$site->sys_sona(array(sona => "Alates", tyyp=>"editor"))?>:</td>
        <td> 
          <input id="algus"  name="algus" size=10 value="<?=$algus_aeg?>" class="scms_flex_input" maxlength="10" style="width:64px" onkeyup="javascript: if(event.keyCode==13){this.form.submit();}">
        </td>
        <td><a href="#" onclick="init_datepicker('algus');"><img src="<?=$site->CONF['wwwroot'].$site->CONF['styles_path']?>/gfx/calendar/cal.gif" width="16" height="15" title="Choose from calendar" alt="Choose from calendar" border="0"></a>
        </td>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,7 +103,10 @@
 
 		<?###### search box ######?>
 		<form id="searchform" name="searchform" action="<?=$site->self?>" method="GET">
-	<? foreach($site->fdat as $fdat_field=>$fdat_value) { ?>
+	<? foreach($site->fdat as $fdat_field=>$fdat_value) {
+	$fdat_value = htmlspecialchars(xss_clean($fdat_value));
+	$fdat_field = htmlspecialchars(xss_clean($fdat_field)); 
+	?>
 		<input type=hidden name="<?=$fdat_field?>" value="<?=$fdat_value?>">
 	<? } ?>
 		<input type="hidden" name="otsi" value=1>
@@ -112,7 +115,7 @@
 		
 		<td style="padding-right: 10px">
 			<? $search_str = $site->sys_sona(array(sona => "otsi", tyyp=>"editor")); ?>
-	          <input name="filter" type="text" class="scms_flex_input" style="width:150px" value="<?=$site->fdat['filter']? $site->fdat['filter'] : $search_str.':'?>" onFocus="if(this.value=='<?=$search_str?>:') this.value='';" onBlur="if(this.value=='')this.value='<?=$search_str?>:';" onkeyup="javascript: if(event.keyCode==13){this.form.submit();}">
+	          <input name="filter" type="text" class="scms_flex_input" style="width:150px" value="<?=$site->fdat['filter']? htmlspecialchars(xss_clean($site->fdat['filter'])) : $search_str.':'?>" onFocus="if(this.value=='<?=$search_str?>:') this.value='';" onBlur="if(this.value=='')this.value='<?=$search_str?>:';" onkeyup="javascript: if(event.keyCode==13){this.form.submit();}">
 
 		</td>
 
```
