# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1408_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1408_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 57-98 of the vulnerable file.

        <input type="hidden" name="action" value="delete"/>
        <input type="hidden" name="mid" value="<?php echo $mid ?>"/>
        <div id="contentButtons">
          <?php echo makePopupButton('?view=zone&mid=' . $mid . '&zid=0', 'zmZone', array('zone', $monitor->Width(), $monitor->Height()), translate('AddNewZone'), canEdit('Monitors')); ?>
          <input type="submit" name="deleteBtn" value="<?php echo translate('Delete') ?>" disabled="disabled"/>
        </div>
        <table id="contentTable" class="major" cellspacing="0">
          <thead>
            <tr>
              <th class="colName"><?php echo translate('Name') ?></th>
              <th class="colType"><?php echo translate('Type') ?></th>
              <th class="colUnits"><?php echo translate('AreaUnits') ?></th>
              <th class="colMark"><?php echo translate('Mark') ?></th>
            </tr>
          </thead>
          <tbody>
<?php
foreach( $zones as $zone ) {
?>
            <tr>
              <td class="colName"><?php echo makePopupLink('?view=zone&mid=' . $mid . '&zid=' . $zone['Id'], 'zmZone', array('zone', $monitor->Width(), $monitor->Height()), $zone['Name'], true, 'onclick="streamCmdQuit( true ); return( false );"'); ?></td>
              <td class="colType"><?php echo $zone['Type'] ?></td>
              <td class="colUnits"><?php echo $zone['Area'] ?>&nbsp;/&nbsp;<?php echo sprintf( "%.2f", ($zone['Area']*100)/($monitor->Width()*$monitor->Height()) ) ?></td>
              <td class="colMark"><input type="checkbox" name="markZids[]" value="<?php echo $zone['Id'] ?>" data-on-click-this="configureDeleteButton"<?php if ( !canEdit( 'Monitors' ) ) { ?> disabled="disabled"<?php } ?>/></td>
            </tr>
<?php
}
?>
          </tbody>
        </table>
        <div class="ZonesImage" style="position:relative; clear:both;">
        <?php echo getStreamHTML( $monitor ); ?>
        <svg class="zones" width="<?php echo $monitor->Width() ?>" height="<?php echo $monitor->Height() ?>" style="position:absolute; top: 0; left: 0; background: none;">
<?php
      foreach( array_reverse($zones) as $zone ) {
?>
          <polygon points="<?php echo $zone['AreaCoords'] ?>" class="popup-link <?php echo $zone['Type']?>" onclick="streamCmdQuit( true ); return( false );"
                   data-url="?view=zone&amp;mid=<?php echo $mid ?>&amp;zid=<?php echo $zone['Id'] ?>"
                   data-window-name="zmZone"
                   data-window-tag="zone"
                   data-window-width="<?php echo $monitor->Width ?>"
                   data-window-height="<?php echo $monitor->Height ?>"/>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,8 +74,8 @@
 foreach( $zones as $zone ) {
 ?>
             <tr>
-              <td class="colName"><?php echo makePopupLink('?view=zone&mid=' . $mid . '&zid=' . $zone['Id'], 'zmZone', array('zone', $monitor->Width(), $monitor->Height()), $zone['Name'], true, 'onclick="streamCmdQuit( true ); return( false );"'); ?></td>
-              <td class="colType"><?php echo $zone['Type'] ?></td>
+              <td class="colName"><?php echo makePopupLink('?view=zone&mid=' . $mid . '&zid=' . $zone['Id'], 'zmZone', array('zone', $monitor->Width(), $monitor->Height()), validHtmlStr($zone['Name']), true, 'onclick="streamCmdQuit( true ); return( false );"'); ?></td>
+              <td class="colType"><?php echo validHtmlStr($zone['Type']) ?></td>
               <td class="colUnits"><?php echo $zone['Area'] ?>&nbsp;/&nbsp;<?php echo sprintf( "%.2f", ($zone['Area']*100)/($monitor->Width()*$monitor->Height()) ) ?></td>
               <td class="colMark"><input type="checkbox" name="markZids[]" value="<?php echo $zone['Id'] ?>" data-on-click-this="configureDeleteButton"<?php if ( !canEdit( 'Monitors' ) ) { ?> disabled="disabled"<?php } ?>/></td>
             </tr>
```
