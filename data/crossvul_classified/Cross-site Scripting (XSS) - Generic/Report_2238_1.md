# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2238_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2238_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 344-384 of the vulnerable file.

                            <?php if ( $thisfilterxsshtml == true) { echo " selected='selected'";}?>
                            ><?php $clang->eT("Yes"); ?></option>
                        <option value='0'
                            <?php if ( $thisfilterxsshtml == false) { echo " selected='selected'";}?>
                            ><?php $clang->eT("No"); ?></option>
			    </select>&nbsp;<span class='hint'><?php $clang->eT("(XSS filtering is always disabled for the superadministrator.)"); ?></span></li>

                <?php $thisusercontrolSameGroupPolicy=getGlobalSetting('usercontrolSameGroupPolicy'); ?>
                <li><label for='usercontrolSameGroupPolicy'><?php $clang->eT("Group member can only see own group:"); ?></label>
                    <select id='usercontrolSameGroupPolicy' name='usercontrolSameGroupPolicy'>
                        <option value='1'
                            <?php if ( $thisusercontrolSameGroupPolicy == true) { echo " selected='selected'";}?>
                            ><?php $clang->eT("Yes"); ?></option>
                        <option value='0'
                            <?php if ( $thisusercontrolSameGroupPolicy == false) { echo " selected='selected'";}?>
                            ><?php $clang->eT("No"); ?></option>
                    </select></li>

                <?php $thisforce_ssl = getGlobalSetting('force_ssl');
                    $opt_force_ssl_on = $opt_force_ssl_off = $opt_force_ssl_neither = '';
                    $warning_force_ssl = sprintf($clang->gT('Warning: Before turning on HTTPS,%s check if this link works.%s'),'<a href="https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'].'" title="'. $clang->gT('Test if your server has SSL enabled by clicking on this link.').'">','</a>')
                    .'<br/> '
                    . $clang->gT("If the link does not work and you turn on HTTPS, LimeSurvey will break and you won't be able to access it.");
                    switch($thisforce_ssl)
                    {
                        case 'on':
                            $warning_force_ssl = '&nbsp;';
                            break;
                        case 'off':
                        case 'neither':
                            break;
                        default:
                            $thisforce_ssl = 'neither';
                    };
                    $this_opt = 'opt_force_ssl_'.$thisforce_ssl;
                    $$this_opt = ' selected="selected"';
                ?><li><label for="force_ssl"><?php $clang->eT('Force HTTPS:'); ?></label>
                    <select name="force_ssl" id="force_ssl">
                        <option value="on" <?php echo $opt_force_ssl_on; ?>><?php $clang->eT('On'); ?></option>
                        <option value="off" <?php echo $opt_force_ssl_off; ?>><?php $clang->eT('Off'); ?></option>
                        <option value="neither" <?php echo $opt_force_ssl_neither; ?>><?php $clang->eT("Don't force on or off"); ?></option>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -361,7 +361,7 @@
 
                 <?php $thisforce_ssl = getGlobalSetting('force_ssl');
                     $opt_force_ssl_on = $opt_force_ssl_off = $opt_force_ssl_neither = '';
-                    $warning_force_ssl = sprintf($clang->gT('Warning: Before turning on HTTPS,%s check if this link works.%s'),'<a href="https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'].'" title="'. $clang->gT('Test if your server has SSL enabled by clicking on this link.').'">','</a>')
+                    $warning_force_ssl = sprintf($clang->gT('Warning: Before turning on HTTPS,%s check if this link works.%s'),'<a href="https://'.$_SERVER['HTTP_HOST'].$this->createUrl("admin/globalsettings/sa").'" title="'. $clang->gT('Test if your server has SSL enabled by clicking on this link.').'">','</a>')
                     .'<br/> '
                     . $clang->gT("If the link does not work and you turn on HTTPS, LimeSurvey will break and you won't be able to access it.");
                     switch($thisforce_ssl)
```
