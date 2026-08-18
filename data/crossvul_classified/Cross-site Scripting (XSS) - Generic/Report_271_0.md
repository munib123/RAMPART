# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 271_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `271_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 107-147 of the vulnerable file.

					</a>
					<ul class="dropdown-menu dropdown-menu-right dropdown-yellow dropdown-caret dropdown-closer">
						<?php
							$t_url = 'manage_filter_edit_page.php?filter_id=' . $f_filter_id . '&view_type=';
							filter_print_view_type_toggle( $t_url, $t_filter['_view_type'] );
						?>
					</ul>
				</div>
			</div>

		</div>

		<div class="widget-body">
			<div class="widget-main no-padding">

				<div class="widget-toolbox padding-8 clearfix">
					<div class="btn-toolbar pull-left">
						<div class="form-inline">
							<label>
								<?php echo lang_get( 'query_name' ) ?>&nbsp;
								<input type="text" size="25" name="filter_name" maxlength="64" value="<?php echo filter_get_field( $f_filter_id, 'name' ) ?>">
							</label>
						</div>
					</div>
				</div>

				<div class="table-responsive">
					<?php
					$t_for_screen = true;
					$t_static = gpc_get_bool( 'static', false );
					filter_form_draw_inputs( $t_filter, $t_for_screen, $t_static );
					?>
				</div>

				<div class="widget-toolbox padding-8 clearfix">
					<div class="btn-toolbar pull-left">
						<div class="form-inline">
							<label><?php echo lang_get( 'search' ) ?>&nbsp;
								<input type="text" id="filter-search-txt" class="input-sm" size="16"
									   name="<?php echo FILTER_PROPERTY_SEARCH ?>"
									   value="<?php echo string_attribute( $t_filter[FILTER_PROPERTY_SEARCH] ) ?>">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -124,7 +124,7 @@
 						<div class="form-inline">
 							<label>
 								<?php echo lang_get( 'query_name' ) ?>&nbsp;
-								<input type="text" size="25" name="filter_name" maxlength="64" value="<?php echo filter_get_field( $f_filter_id, 'name' ) ?>">
+								<input type="text" size="25" name="filter_name" maxlength="64" value="<?php echo string_display_line( filter_get_field( $f_filter_id, 'name' ) ) ?>">
 							</label>
 						</div>
 					</div>
```
