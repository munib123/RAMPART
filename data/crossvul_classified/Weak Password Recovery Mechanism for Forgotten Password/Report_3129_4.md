# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 3129_4
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3129_4`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php $view->script('uikit-form-password') ?>

<form class="pk-user pk-user-reset uk-form uk-form-stacked uk-width-medium-1-2 uk-width-large-1-3 uk-container-center" action="<?= $view->url('@user/resetpassword/confirm', ['user' => $username, 'key' => $activation]) ?>" method="post">

    <?php if($error): ?>
    <div class="uk-alert uk-alert-danger">
        <?= $error; ?>
    </div>
    <?php endif; ?>

    <h1 class="uk-h2 uk-text-center"><?= __('Password Confirmation') ?></h1>

    <div class="uk-form-row js-password">
        <div class="uk-form-password uk-width-1-1">
            <input class="uk-width-1-1" type="password" name="password" value="" placeholder="<?= __('New Password') ?>">
            <a href="" class="uk-form-password-toggle" tabindex="-1" data-uk-form-password="{ lblShow: '<?= __('Show') ?>', lblHide: '<?= __('Hide') ?>' }"><?= __('Show') ?></a>
        </div>
    </div>

    <p class="uk-form-row">
        <button class="uk-button uk-button-primary uk-button-large uk-width-1-1" type="submit"><?= __('Confirm') ?></button>
    </p>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 <?php $view->script('uikit-form-password') ?>
 
-<form class="pk-user pk-user-reset uk-form uk-form-stacked uk-width-medium-1-2 uk-width-large-1-3 uk-container-center" action="<?= $view->url('@user/resetpassword/confirm', ['user' => $username, 'key' => $activation]) ?>" method="post">
+<form class="pk-user pk-user-reset uk-form uk-form-stacked uk-width-medium-1-2 uk-width-large-1-3 uk-container-center" action="<?= $view->url('@user/resetpassword/confirm', ['key' => $activation]) ?>" method="post">
 
     <?php if($error): ?>
     <div class="uk-alert uk-alert-danger">
```
