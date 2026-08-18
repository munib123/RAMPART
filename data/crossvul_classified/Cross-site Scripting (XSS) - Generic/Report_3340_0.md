# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3340_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3340_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 85-119 of the vulnerable file.

                <?php if ($config['reg']) {
    ?><li><a href="reg.php">註冊</a></li><?php 
}
            ?>
                <?php if ($config['tos']) {
    ?><li><a href="tos.php">使用條款</a></li><?php 
}
            ?>
            </ul>
        <?php 
        } ?>
    <div class="jumbotron">
        <?php if ($show) {
    ?>
        <h1><?php echo $res[0]['name'];
    ?></h1>
        <p>擁有者：<?php echo $res[0]['owner'];
    ?></br>檔案大小：<?php sizecount($res[0]['size'] / 1000 / 1000);
    ?></br>上傳時間：<?php echo $res[0]['date'];
    ?></p>
        <p><a href="rdownfile.php?id=<?php echo $_GET['id'];
    ?>&password=<?php echo $_GET['password'];
    ?>" class="btn btn-large btn-primary">下載</a></p>
        <?php 
} else {
    ?>
        <h1>404 Not Found</h1>
        <p>此檔案不存在，可能不存在、已經被刪除或是被設定為不公開。</p>
        <?php 
} ?>
    </div>
    <p class="text-center text-info">Proudly Powered by <a href="http://ad.allenchou.cc/">Allen Disk</a></p>
</div>
</body>
</html>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,8 +102,8 @@
     ?></br>檔案大小：<?php sizecount($res[0]['size'] / 1000 / 1000);
     ?></br>上傳時間：<?php echo $res[0]['date'];
     ?></p>
-        <p><a href="rdownfile.php?id=<?php echo $_GET['id'];
-    ?>&password=<?php echo $_GET['password'];
+        <p><a href="rdownfile.php?id=<?php echo htmlspecialchars($_GET['id']);
+    ?>&password=<?php echo htmlspecialchars($_GET['password']);
     ?>" class="btn btn-large btn-primary">下載</a></p>
         <?php 
 } else {
```
