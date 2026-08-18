# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 751_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `751_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 84-124 of the vulnerable file.

    </div>
    <div class="loading">
        <div class="spinner"></div>
        <div class="loadingText"><?php echo __('Loading');?></div>
    </div>

    <script type="text/javascript">
    <?php
        if (!isset($debugMode)):
    ?>
        $(window).scroll(function(e) {
            $('.actions').css('left',-$(window).scrollLeft());
        });
    <?php
        endif;
    ?>
        var tabIsActive = true;
        var baseurl = '<?php echo $baseurl; ?>';
        var here = '<?php
                if (substr($this->params['action'], 0, 6) === 'admin_') {
                    echo $baseurl . '/admin/' . $this->params['controller'] . '/' . substr($this->params['action'], 6);
                } else {
                    echo $baseurl . '/' . $this->params['controller'] . '/' . $this->params['action'];
                }
            ?>';
        $(document).ready(function(){
            $(window).blur(function() {
                tabIsActive = false;
            });
            $(window).focus(function() {
                tabIsActive = true;
            });
        <?php
            if (!Configure::read('MISP.disable_auto_logout') and $me):
        ?>
                checkIfLoggedIn();
        <?php
            endif;
        ?>
        if ($('.alert').text().indexOf("$flashErrorMessage") >= 0) {
            //$('#flashErrorMessage').html()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,9 +101,9 @@
         var baseurl = '<?php echo $baseurl; ?>';
         var here = '<?php
                 if (substr($this->params['action'], 0, 6) === 'admin_') {
-                    echo $baseurl . '/admin/' . $this->params['controller'] . '/' . substr($this->params['action'], 6);
+                    echo $baseurl . '/admin/' . h($this->params['controller']) . '/' . h(substr($this->params['action'], 6));
                 } else {
-                    echo $baseurl . '/' . $this->params['controller'] . '/' . $this->params['action'];
+                    echo $baseurl . '/' . h($this->params['controller']) . '/' . h($this->params['action']);
                 }
             ?>';
         $(document).ready(function(){
```
