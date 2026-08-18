# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1409_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1409_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 46-86 of the vulnerable file.

          <thead>
            <tr>
              <th class="colName"><?php echo translate('Name') ?></th>
              <th class="colType"><?php echo translate('Type') ?></th>
              <th class="colProtocol"><?php echo translate('Protocol') ?></th>
              <th class="colCanMove"><?php echo translate('CanMove') ?></th>
              <th class="colCanZoom"><?php echo translate('CanZoom') ?></th>
              <th class="colCanFocus"><?php echo translate('CanFocus') ?></th>
              <th class="colCanIris"><?php echo translate('CanIris') ?></th>
              <th class="colCanWhiteBal"><?php echo translate('CanWhiteBal') ?></th>
              <th class="colHasPresets"><?php echo translate('HasPresets') ?></th>
              <th class="colMark"><?php echo translate('Mark') ?></th>
            </tr>
          </thead>
          <tbody>
<?php
foreach( $controls as $control )
{
?>
            <tr>
              <td class="colName"><?php echo makePopupLink( '?view=controlcap&cid='.$control['Id'], 'zmControlCap', 'controlcap', $control['Name'], canView( 'Control' ) ) ?></td>
              <td class="colType"><?php echo $control['Type'] ?></td>
              <td class="colProtocol"><?php echo $control['Protocol'] ?></td>
              <td class="colCanMove"><?php echo $control['CanMove']?translate('Yes'):translate('No') ?></td>
              <td class="colCanZoom"><?php echo $control['CanZoom']?translate('Yes'):translate('No') ?></td>
              <td class="colCanFocus"><?php echo $control['CanFocus']?translate('Yes'):translate('No') ?></td>
              <td class="colCanIris"><?php echo $control['CanIris']?translate('Yes'):translate('No') ?></td>
              <td class="colCanWhiteBal"><?php echo $control['CanWhite']?translate('Yes'):translate('No') ?></td>
              <td class="colHasPresets"><?php echo $control['HasHomePreset']?'H':'' ?><?php echo $control['HasPresets']?$control['NumPresets']:'0' ?></td>
              <td class="colMark"><input type="checkbox" name="markCids[]" value="<?php echo $control['Id'] ?>" data-on-click-this="configureDeleteButton"<?php if ( !canEdit( 'Control' ) ) {?> disabled="disabled"<?php } ?>/></td>
            </tr>
<?php
}
?>
          </tbody>
        </table>
        <div id="contentButtons">
          <?php echo makePopupButton('?view=controlcap', 'zmControlCap', 'controlcap', translate('AddNewControl'), canEdit( 'Control' )); ?>
          <input type="submit" name="deleteBtn" value="<?php echo translate('Delete') ?>" disabled="disabled"/>
        </div>
      </form>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,9 +63,9 @@
 {
 ?>
             <tr>
-              <td class="colName"><?php echo makePopupLink( '?view=controlcap&cid='.$control['Id'], 'zmControlCap', 'controlcap', $control['Name'], canView( 'Control' ) ) ?></td>
+              <td class="colName"><?php echo makePopupLink( '?view=controlcap&cid='.$control['Id'], 'zmControlCap', 'controlcap', validHtmlStr($control['Name']), canView( 'Control' ) ) ?></td>
               <td class="colType"><?php echo $control['Type'] ?></td>
-              <td class="colProtocol"><?php echo $control['Protocol'] ?></td>
+              <td class="colProtocol"><?php echo validHtmlStr($control['Protocol']) ?></td>
               <td class="colCanMove"><?php echo $control['CanMove']?translate('Yes'):translate('No') ?></td>
               <td class="colCanZoom"><?php echo $control['CanZoom']?translate('Yes'):translate('No') ?></td>
               <td class="colCanFocus"><?php echo $control['CanFocus']?translate('Yes'):translate('No') ?></td>
```
