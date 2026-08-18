# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1685_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1685_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<?php
	//only admins can get this
	if(!function_exists("current_user_can") || (!current_user_can("manage_options") && !current_user_can("pmpro_memberslist")))
	{
		die(__("You do not have permissions to perform this action.", "pmpro"));
	}

	//vars
	global $wpdb;
	if(isset($_REQUEST['s']))
		$s = trim($_REQUEST['s']);
	else
		$s = "";

	if(isset($_REQUEST['l']))
		$l = $_REQUEST['l'];
	else
		$l = false;

	require_once(dirname(__FILE__) . "/admin_header.php");
?>

	<form id="posts-filter" method="get" action="">
	<h2>
		<?php _e('Members List', 'pmpro');?>
		<a target="_blank" href="<?php echo admin_url('admin-ajax.php');?>?action=memberslist_csv&s=<?php echo $s?>&l=<?php echo $l?>" class="add-new-h2"><?php _e('Export to CSV', 'pmpro');?></a>
	</h2>
	<ul class="subsubsub">
		<li>
			<?php _e('Show', 'pmpro');?>
			<select name="l" onchange="jQuery('#posts-filter').submit();">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,12 +8,12 @@
 	//vars
 	global $wpdb;
 	if(isset($_REQUEST['s']))
-		$s = trim($_REQUEST['s']);
+		$s = sanitize_text_field(trim($_REQUEST['s']));
 	else
 		$s = "";
 
 	if(isset($_REQUEST['l']))
-		$l = $_REQUEST['l'];
+		$l = intval($_REQUEST['l']);
 	else
 		$l = false;
 
@@ -23,7 +23,7 @@
 	<form id="posts-filter" method="get" action="">
 	<h2>
 		<?php _e('Members List', 'pmpro');?>
-		<a target="_blank" href="<?php echo admin_url('admin-ajax.php');?>?action=memberslist_csv&s=<?php echo $s?>&l=<?php echo $l?>" class="add-new-h2"><?php _e('Export to CSV', 'pmpro');?></a>
+		<a target="_blank" href="<?php echo admin_url('admin-ajax.php');?>?action=memberslist_csv&s=<?php echo esc_attr($s);?>&l=<?php echo $l?>" class="add-new-h2"><?php _e('Export to CSV', 'pmpro');?></a>
 	</h2>
 	<ul class="subsubsub">
 		<li>
@@ -48,7 +48,7 @@
 	<p class="search-box">
 		<label class="hidden" for="post-search-input"><?php _e('Search Members', 'pmpro');?>:</label>
 		<input type="hidden" name="page" value="pmpro-memberslist" />
-		<input id="post-search-input" type="text" value="<?php echo $s?>" name="s"/>
+		<input id="post-search-input" type="text" value="<?php echo esc_attr($s);?>" name="s"/>
 		<input class="button" type="submit" value="<?php _e('Search Members', 'pmpro');?>"/>
 	</p>
 	<?php
@@ -211,7 +211,7 @@
 							</td>
 							<td><?php echo $theuser->first_name?></td>
 							<td><?php echo $theuser->last_name?></td>
-							<td><a href="mailto:<?php echo $theuser->user_email?>"><?php echo $theuser->user_email?></a></td>
+							<td><a href="mailto:<?php echo esc_attr($theuser->user_email)?>"><?php echo $theuser->user_email?></a></td>
 							<?php do_action("pmpro_memberslist_extra_cols_body", $theuser);?>
 							<td>
 								<?php
@@ -248,7 +248,7 @@
 				{
 				?>
 				<tr>
-					<td colspan="9"><p><?php _e("No members found.", "pmpro");?> <?php if($l) { ?><a href="?page=pmpro-memberslist&s=<?php echo $s?>"><?php _e("Search all levels", "pmpro");?></a>.<?php } ?></p></td>
+					<td colspan="9"><p><?php _e("No members found.", "pmpro");?> <?php if($l) { ?><a href="?page=pmpro-memberslist&s=<?php echo esc_attr($s);?>"><?php _e("Search all levels", "pmpro");?></a>.<?php } ?></p></td>
 				</tr>
 				<?php
 				}
```
