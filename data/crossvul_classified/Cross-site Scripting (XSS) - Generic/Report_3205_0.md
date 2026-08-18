# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3205_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3205_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 368-403 of the vulnerable file.

		&& access_has_bug_level( config_get( 'time_tracking_edit_threshold' ), $f_bug_id )
	) {
	?>
			<tr>
				<th class="category">
					<?php echo lang_get( 'time_tracking' ) ?>
				</th>
				<td>
					<input type="text" name="time_tracking" class="input-sm" size="5" placeholder="hh:mm" />
				</td>
			</tr>

<?php
	}

	event_signal( 'EVENT_BUGNOTE_ADD_FORM', array( $f_bug_id ) );
?>

</tbody>
</table>
<input type="hidden" name="action_type" value="<?php echo $f_change_type; ?>" />

</div>
</div>
<div class="widget-toolbox padding-8 clearfix">
	<input type="submit" class="btn btn-primary btn-white btn-round" value="<?php echo lang_get( $t_status_label . '_bug_button' ) ?>" />
</div>
</div>
</div>
</div>
</form>
<div class="space-10"></div>
</div>
<?php
define( 'BUG_VIEW_INC_ALLOW', true );
include( dirname( __FILE__ ) . '/bug_view_inc.php' );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -385,7 +385,7 @@
 
 </tbody>
 </table>
-<input type="hidden" name="action_type" value="<?php echo $f_change_type; ?>" />
+<input type="hidden" name="action_type" value="<?php echo string_attribute( $f_change_type ); ?>" />
 
 </div>
 </div>
```
