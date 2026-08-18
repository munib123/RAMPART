# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1034_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1034_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 105-145 of the vulnerable file.

		<input type="text" name="title" class="input-sm" size="70" maxlength="250" value="<?php echo $v_title ?>" required />
	</td>
</tr>
<tr>
	<th class="category">
		<?php echo lang_get( 'description' ) ?>
	</th>
	<td>
		<textarea class="form-control" name="description" cols="60" rows="7"><?php echo $v_description ?></textarea>
	</td>
</tr>
<tr>
	<th class="category">
		<?php echo lang_get( 'filename' ) ?>
	</th>
	<td>
		<?php
			$t_href = '<a href="file_download.php?file_id='.$v_id.'&amp;type=doc">';
			echo $t_href;
			print_file_icon( $v_filename );
			echo '</a>&#160;' . $t_href . file_get_display_name( $v_filename ) . '</a>';
		?>
	</td>
</tr>
<tr>
	<td class="category">
		<?php echo lang_get( 'select_file' ); ?>
		<br />
		<?php print_max_filesize( $t_max_file_size ); ?>
	</td>
	<td>
		<input type="hidden" name="max_file_size" value="<?php echo $t_max_file_size ?>" />
		<input name="file" type="file" size="70" />
	</td>
<tr>
</table>
</div>
</div>
	<div class="widget-toolbox padding-8 clearfix">
		<span class="required pull-right"> * <?php echo lang_get('required') ?></span>
		<input type="submit" class="btn btn-primary btn-white btn-round"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,7 +122,7 @@
 			$t_href = '<a href="file_download.php?file_id='.$v_id.'&amp;type=doc">';
 			echo $t_href;
 			print_file_icon( $v_filename );
-			echo '</a>&#160;' . $t_href . file_get_display_name( $v_filename ) . '</a>';
+			echo '</a>&#160;' . $t_href . string_html_specialchars( file_get_display_name( $v_filename ) ) . '</a>';
 		?>
 	</td>
 </tr>
```
