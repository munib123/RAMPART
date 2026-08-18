# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4024_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4024_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 67-104 of the vulnerable file.

                                    <li>Database Connection</li>
                                    <li>Database Creation</li>
                                    <li>School Information</li>
                                    <li>Site Admin Account Setup</li>
                                    <li>Ready to Go!</li>
                                </ul>
                                <!--<h4 class="no-margin">Installation Prerequisite</h4>
                                <p>Before you install openSIS, you need to have Apache web server, MySQL database server and php scripting language setup in your machine.</p>
                                <p>You can download an all-inclusive package from: <a href="https://www.apachefriends.org/download.html">https://www.apachefriends.org/download.html</a></p>
                                <p>Select the download package for the operating system you are using on your machine. Install that first and then start the openSIS installer.</p>-->
                            </div>
                            <div class="installation-steps">
                                <table style="height:270px; width: 70%;" border="0" cellspacing="12" cellpadding="12" align="center">
                                    <tr>
                                        <?php
                                        if ($_GET["upreq"] == 'true') {
                                            echo '<td>You were redirected to this page because an upgrade is needed.<br> Please, proceed using the action below.</td>';
                                            echo '</tr><tr>';
                                            echo '<td valign="middle" align="center"><a href="Step0.1.php?mod=upgrade"><img src="assets/images/icon-upgrade.png" alt="Upgrade OpenSIS" /><br/><h5 class="text-black"><b>Upgrade</b><br/><small>(From ver 4.7 thru 6.0)</small></h5></a></td>';
                                        } else {
                                            echo '<td valign="middle" align="center"><a href="SystemCheck.php"><img src="assets/images/icon-package.png" alt="New Installation" /><br/><h5 class="text-black"><b>New Installation</b><br/><small>(Ver 7.3)</small></h5></a></td>';
                                            echo '<td valign="middle" align="center"><a href="Step0.1.php?mod=upgrade"><img src="assets/images/icon-upgrade.png" alt="Upgrade OpenSIS"/><br/><h5 class="text-black"><b>Upgrade</b><br/><small>(From ver 7.1 onwards)</small></h5></a></td>';
                                        }
                                        ?>
                                    </tr>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                <footer>
                    Copyright &copy; Open Solutions for Education, Inc. (<a href="http://www.os4ed.com">OS4ED</a>).
                </footer>
            </div>
        </section>
    </body>
</html>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,7 +84,7 @@
                                             echo '</tr><tr>';
                                             echo '<td valign="middle" align="center"><a href="Step0.1.php?mod=upgrade"><img src="assets/images/icon-upgrade.png" alt="Upgrade OpenSIS" /><br/><h5 class="text-black"><b>Upgrade</b><br/><small>(From ver 4.7 thru 6.0)</small></h5></a></td>';
                                         } else {
-                                            echo '<td valign="middle" align="center"><a href="SystemCheck.php"><img src="assets/images/icon-package.png" alt="New Installation" /><br/><h5 class="text-black"><b>New Installation</b><br/><small>(Ver 7.3)</small></h5></a></td>';
+                                            echo '<td valign="middle" align="center"><a href="SystemCheck.php"><img src="assets/images/icon-package.png" alt="New Installation" /><br/><h5 class="text-black"><b>New Installation</b><br/><small>(Ver 7.4)</small></h5></a></td>';
                                             echo '<td valign="middle" align="center"><a href="Step0.1.php?mod=upgrade"><img src="assets/images/icon-upgrade.png" alt="Upgrade OpenSIS"/><br/><h5 class="text-black"><b>Upgrade</b><br/><small>(From ver 7.1 onwards)</small></h5></a></td>';
                                         }
                                         ?>
```
