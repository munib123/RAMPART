# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 58_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `58_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 199-223 of the vulnerable file.

			}
			?>
		</select>
	</td>
	<td class="info2">
		<?php print _('Select menu type to display'); ?>
	</td>
</tr>


<!-- Submit and hidden values -->
<tr class="th">
    <td></td>
    <td class="submit">
        <input type="submit" class="btn btn-sm btn-success pull-right" value="<?php print _('Save changes'); ?>">
    </td>
    <td></td>
</tr>

</table>
</form>


<!-- result -->
<div class="userModSelfResult" style="margin-bottom:90px;display:none"></div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -216,6 +216,7 @@
 </tr>
 
 </table>
+<input type="hidden" name="csrf_cookie" value="<?php print $csrf; ?>">
 </form>
 
 
```
