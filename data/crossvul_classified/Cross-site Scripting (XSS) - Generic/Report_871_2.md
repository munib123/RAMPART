# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 871_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `871_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 141-181 of the vulnerable file.

?>
<form action="acme_accountkeys.php" method="post">
	<div class="panel panel-default">
		<div class="panel-heading">
			<h2 class="panel-title">Account keys</h2>
		</div>
		<div id="mainarea" class="table-responsive panel-body">
			<table class="table table-hover table-striped table-condensed">
				<thead>
					<tr>
						<th></th>
						<th width="30%">Name</th>
						<th width="20%">Description</th>
						<th>CA</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody class="user-entries">
<?php
		foreach ($a_accountkeys as $accountkey) {
			$accountname = $accountkey['name'];
			?>
			<tr id="fr<?=$accountname;?>" <?=$display?> onClick="fr_toggle('<?=$accountname;?>')" ondblclick="document.location='acme_accountkeys_edit.php?id=<?=$accountname;?>';">
				<td>
					<input type="checkbox" id="frc<?=$accountname;?>" onClick="fr_toggle('<?=$accountname;?>')" name="rule[]" value="<?=$accountname;?>"/>
					<a class="fa fa-anchor" id="Xmove_<?=$accountname?>" title="<?=gettext("Move checked entries to here")?>"></a>
				</td>
			  <td>
				<?=$accountkey['name'];?>
			  </td>
			  <td>
				<?=$accountkey['desc'];?>
			  </td>
			  <td>
				<?=$accountkey['acmeserver'];?>
			  </td>
			  <td class="action-icons">
				<button style="display: none;" class="btn btn-default btn-xs" type="submit" id="move_<?=$accountname?>" name="move_<?=$accountname?>" value="move_<?=$accountname?>"></button>
				<a href="acme_accountkeys_edit.php?id=<?=$accountname;?>">
					<?=acmeicon("edit", gettext("edit"))?>
				</a>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,7 +158,7 @@
 				<tbody class="user-entries">
 <?php
 		foreach ($a_accountkeys as $accountkey) {
-			$accountname = $accountkey['name'];
+			$accountname = htmlspecialchars($accountkey['name']);
 			?>
 			<tr id="fr<?=$accountname;?>" <?=$display?> onClick="fr_toggle('<?=$accountname;?>')" ondblclick="document.location='acme_accountkeys_edit.php?id=<?=$accountname;?>';">
 				<td>
@@ -166,13 +166,13 @@
 					<a class="fa fa-anchor" id="Xmove_<?=$accountname?>" title="<?=gettext("Move checked entries to here")?>"></a>
 				</td>
 			  <td>
-				<?=$accountkey['name'];?>
+				<?=$accountname;?>
 			  </td>
 			  <td>
-				<?=$accountkey['desc'];?>
+				<?=htmlspecialchars($accountkey['desc']);?>
 			  </td>
 			  <td>
-				<?=$accountkey['acmeserver'];?>
+				<?=htmlspecialchars($accountkey['acmeserver']);?>
 			  </td>
 			  <td class="action-icons">
 				<button style="display: none;" class="btn btn-default btn-xs" type="submit" id="move_<?=$accountname?>" name="move_<?=$accountname?>" value="move_<?=$accountname?>"></button>
```
