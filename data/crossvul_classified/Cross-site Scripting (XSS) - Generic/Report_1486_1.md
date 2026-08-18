# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1486_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1486_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 156-196 of the vulnerable file.

	<TR>
		<!-- Left column -->
		<TD class="scms_left">

			<div id=navigation class="scms_left_div">
				<table style="width:100%;height:100%"  border="0" cellpadding="0" cellspacing="0">
			<!-- Search -->
					<tr>
						<td valign=top>
			<?
			#################
			# SEARCH BOX
			?>
			<? $search_str = $site->sys_sona(array(sona => "otsi", tyyp=>"editor")); ?>
						<TABLE width="20%" border="0" cellpadding="0" cellspacing="0" bgcolor=white style="padding-left:4; padding-right:4; padding-top:2">
	  <form name="datasearchform" action="<?=$site->self?>" method="GET">
								<TR>
									<TD width="24" nowrap><IMG SRC="<?=$site->CONF['wwwroot'].$site->CONF['styles_path']?>/gfx/menu/search.gif" BORDER="0" ALT="">

									</TD>
									<TD><input name="data_search" type="text" class="scms_flex_input" value="<?=$site->fdat['data_search']? $site->fdat['data_search'] : $search_str.':'?>" onFocus="if(this.value=='<?=$search_str?>:') this.value='';" onBlur="if(this.value=='')this.value='<?=$search_str?>:';" style="width:140px"></TD>
									<?###### wide middle cell ######?>
									<td width="100%"></td>

								</TR>
		<? ######## hidden ########?>
		<input type=hidden name=profile_search value="<?=$site->fdat['profile_search']?>">
		<input type=hidden name=profile_id value="<?=$site->fdat['profile_id']?>">
		</form>
						</TABLE>
			<!-- //Search -->
			<br />
			</td>
			</tr>
	
			<!-- Menu tree -->

					<!-- I grupp -->
					<tr>
						<td valign=top>
	<?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -173,14 +173,14 @@
 									<TD width="24" nowrap><IMG SRC="<?=$site->CONF['wwwroot'].$site->CONF['styles_path']?>/gfx/menu/search.gif" BORDER="0" ALT="">
 
 									</TD>
-									<TD><input name="data_search" type="text" class="scms_flex_input" value="<?=$site->fdat['data_search']? $site->fdat['data_search'] : $search_str.':'?>" onFocus="if(this.value=='<?=$search_str?>:') this.value='';" onBlur="if(this.value=='')this.value='<?=$search_str?>:';" style="width:140px"></TD>
+									<TD><input name="data_search" type="text" class="scms_flex_input" value="<?=$site->fdat['data_search']? htmlspecialchars(xss_clean($site->fdat['data_search'])) : $search_str.':'?>" onFocus="if(this.value=='<?=$search_str?>:') this.value='';" onBlur="if(this.value=='')this.value='<?=$search_str?>:';" style="width:140px"></TD>
 									<?###### wide middle cell ######?>
 									<td width="100%"></td>
 
 								</TR>
 		<? ######## hidden ########?>
-		<input type=hidden name=profile_search value="<?=$site->fdat['profile_search']?>">
-		<input type=hidden name=profile_id value="<?=$site->fdat['profile_id']?>">
+		<input type=hidden name=profile_search value="<?=htmlspecialchars(xss_clean($site->fdat['profile_search']))?>">
+		<input type=hidden name=profile_id value="<?=htmlspecialchars(xss_clean($site->fdat['profile_id']))?>">
 		</form>
 						</TABLE>
 			<!-- //Search -->
```
