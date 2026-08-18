# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2085_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2085_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 19-41 of the vulnerable file.

                    </div>
                </div>
                <div class="col-lg-2">
                    <?php
                        echo $this->getMenu
                        (
                            1,
                            '<div class="panel panel-default">
                                 <div class="panel-heading">%s</div>
                                    <div class="panel-body">
                                        %c
                                    </div>
                             </div>'
                        );
                    ?>
                </div>
            </div>
        </div> 
        <div class="container credit">
            <p class="muted credit">© Ilch CMS | <?php echo '<a href="'.$this->getUrl(array('module' => 'admin', 'controller' => 'admin', 'action' => 'index')).'">Administrator</a>'; ?></p>
        </div>  
    </body>
</html>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,6 @@
         </div> 
         <div class="container credit">
             <p class="muted credit">© Ilch CMS | <?php echo '<a href="'.$this->getUrl(array('module' => 'admin', 'controller' => 'admin', 'action' => 'index')).'">Administrator</a>'; ?></p>
-        </div>  
+        </div>
     </body>
 </html>
```
