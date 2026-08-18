# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2596_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2596_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 255-295 of the vulnerable file.

</div>

<div class="widget-body">
<div class="widget-toolbox padding-8 clearfix">
	<div id="manage-user-div" class="form-container">
		<div class="pull-left">
			<?php print_form_button( 'manage_user_create_page.php', lang_get( 'create_new_account_link' ), null, null, 'btn btn-primary btn-white btn-round' ) ?>
		</div>
		<?php if( $f_filter === 'UNUSED' ) { ?>
		<div class="pull-left">
			<?php print_form_button('manage_user_prune.php', lang_get('prune_accounts'), null, null, 'btn btn-primary btn-white btn-round') ?>
		</div>
		<?php } ?>
	<div class="pull-right">
	<form id="manage-user-filter" method="post" action="manage_user_page.php" class="form-inline">
		<fieldset>
			<?php # CSRF protection not required here - form does not result in modifications ?>
			<input type="hidden" name="sort" value="<?php echo $c_sort ?>" />
			<input type="hidden" name="dir" value="<?php echo $c_dir ?>" />
			<input type="hidden" name="save" value="1" />
			<input type="hidden" name="filter" value="<?php echo $f_filter ?>" />
			<label class="inline">
			<input type="checkbox" class="ace" name="hideinactive" value="<?php echo ON ?>" <?php check_checked( (int)$c_hide_inactive, ON ); ?> />
			<span class="lbl"> <?php echo lang_get( 'hide_inactive' ) ?></span>
			</label>
			<label class="inline">
			<input type="checkbox" class="ace" name="showdisabled" value="<?php echo ON ?>" <?php check_checked( (int)$c_show_disabled, ON ); ?> />
			<span class="lbl"> <?php echo lang_get( 'show_disabled' ) ?></span>
			</label>
			<input type="submit" class="btn btn-primary btn-sm btn-white btn-round" value="<?php echo lang_get( 'filter_button' ) ?>" />
		</fieldset>
	</form>
		</div>
	</div>
</div>

<div class="widget-main no-padding">
	<div class="table-responsive">
		<table class="table table-striped table-bordered table-condensed table-hover">
		<thead>
			<tr>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -272,7 +272,7 @@
 			<input type="hidden" name="sort" value="<?php echo $c_sort ?>" />
 			<input type="hidden" name="dir" value="<?php echo $c_dir ?>" />
 			<input type="hidden" name="save" value="1" />
-			<input type="hidden" name="filter" value="<?php echo $f_filter ?>" />
+			<input type="hidden" name="filter" value="<?php echo string_attribute( $f_filter ); ?>" />
 			<label class="inline">
 			<input type="checkbox" class="ace" name="hideinactive" value="<?php echo ON ?>" <?php check_checked( (int)$c_hide_inactive, ON ); ?> />
 			<span class="lbl"> <?php echo lang_get( 'hide_inactive' ) ?></span>
```
