# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3206_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3206_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 88-128 of the vulnerable file.

$t_action  = 'view_all_set.php?f=3';

if( $f_for_screen == false ) {
	$t_action  = 'view_all_set.php';
}

$f_static = gpc_get_bool( 'static', false );

$f_view_type = gpc_get_string( 'view_type', $t_filter['_view_type'] );
$t_filter['_view_type'] = $f_view_type;
$t_filter = filter_ensure_valid_filter( $t_filter );

?>
<div class="space-10"></div>
<div class="col-md-12 col-xs-12">

	<form method="post" name="filters" id="filters_form_open" class="form-control" action="<?php echo $t_action; ?>">

	<?php # CSRF protection not required here - form does not result in modifications ?>
	<input type="hidden" name="type" value="1" />
	<input type="hidden" name="view_type" value="<?php echo $f_view_type; ?>" />
	<?php
		if( $f_for_screen == false ) {
			print '<input type="hidden" name="print" value="1" />';
			print '<input type="hidden" name="offset" value="0" />';
		}
	?>

		<div class="widget-box widget-color-blue2">
			<div class="widget-header widget-header-small">
				<h4 class="widget-title lighter">
					<i class="ace-icon fa fa-filter"></i>
					<?php echo lang_get('filters') ?>
				</h4>

				<div class="widget-toolbar">
					<div class="widget-menu">
						<a href="#" data-action="settings" data-toggle="dropdown">
							<i class="ace-icon fa fa-bars bigger-125"></i>
						</a>
						<ul class="dropdown-menu dropdown-menu-right dropdown-yellow dropdown-caret dropdown-closer">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,7 +105,7 @@
 
 	<?php # CSRF protection not required here - form does not result in modifications ?>
 	<input type="hidden" name="type" value="1" />
-	<input type="hidden" name="view_type" value="<?php echo $f_view_type; ?>" />
+	<input type="hidden" name="view_type" value="<?php echo $t_filter['_view_type']; ?>" />
 	<?php
 		if( $f_for_screen == false ) {
 			print '<input type="hidden" name="print" value="1" />';
```
