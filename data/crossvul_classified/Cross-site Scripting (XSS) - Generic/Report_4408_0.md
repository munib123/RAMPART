# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4408_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4408_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 8-43 of the vulnerable file.

require 'includes/header.inc.php';

// Layout borrowed from http://getbootstrap.com/examples/signin/
?>

<h1 class="logo">phpRedisAdmin</h1>

<form class="form-signin" method="post" action="login.php">
    <h2 class="form-signin-heading">Please log in</h2>

    <?php if (isset($_POST['username']) || isset($_POST['password'])): ?>
        <div class="invalid-credentials">
            <h3>Invalid username/password</h3>
            <p>Please try again.</p>
        </div>
    <?php endif; ?>

    <label for="inputUser" class="sr-only">Username</label>
    <input type="text" name="username" id="inputUser" class="form-control"
           placeholder="Username"
           value="<?= isset($_POST['username']) ? $_POST['username'] : '' ?>"
           required <?= isset($_POST['username']) ? '' : 'autofocus' ?>>

    <label for="inputPassword" class="sr-only">Password</label>
    <input type="password" name="password" id="inputPassword" class="form-control"
           placeholder="Password"
           required <?= isset($_POST['username']) ? 'autofocus' : '' ?>>

    <button class="btn btn-lg btn-primary btn-block" type="submit">Log in</button>
</form>

<?php

require 'includes/footer.inc.php';

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
     <label for="inputUser" class="sr-only">Username</label>
     <input type="text" name="username" id="inputUser" class="form-control"
            placeholder="Username"
-           value="<?= isset($_POST['username']) ? $_POST['username'] : '' ?>"
+           value="<?= isset($_POST['username']) ? htmlentities($_POST['username'], defined('ENT_SUBSTITUTE') ? (ENT_QUOTES | ENT_SUBSTITUTE) : ENT_QUOTES, 'utf-8') : '' ?>"
            required <?= isset($_POST['username']) ? '' : 'autofocus' ?>>
 
     <label for="inputPassword" class="sr-only">Password</label>
```
