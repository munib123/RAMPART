# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 385_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `385_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 169-209 of the vulnerable file.

                <?php $class = (isset($item['class'])) ? ($item['class']) : false; ?>
                <?php $html = (isset($item['html'])) ? ($item['html']) : false; ?>
                <a class="mw-ui-btn mw-ui-btn-outline mw-admin-user-tab" href="javascript:;"><?php print $title; ?></a>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
    <div class="mw-ui-box <?php print $config['module_class'] ?> user-id-<?php print $data['id']; ?>" id="users_edit_{rand}">
        <div class="mw-ui-box-header" style="margin-bottom: 0;"><span class="ico iusers"></span>
            <?php if ($data['id'] != 0): ?>
                <span>
    <?php _e("Edit user"); ?>
                    &laquo;
                    <?php print $data['username']; ?>
                    &raquo;</span>
            <?php else: ?>
                <span>
    <?php _e("Add new user"); ?>
    </span>
            <?php endif; ?>
        </div>
        <input type="hidden" class="mw-ui-field" name="id" value="<?php print $data['id']; ?>">
        <div>
            <table btos="0" cellpadding="0" cellspacing="0" class="mw-ui-table mw-ui-table-basic mw-admin-user-tab-content" width="100%">
                <col width="150px"/>
                <tr>
                    <td><label class="mw-ui-label">
                            <?php _e("Avatar"); ?>
                        </label></td>
                    <td><?php if ($data['thumbnail'] == '') { ?>
                            <div id="avatar_holder"><span class="mw-icon-user"></span></div>
                            <span class='mw-ui-link' id="change_avatar">
          <?php _e("Add Image"); ?>
          </span>
                        <?php } else { ?>
                            <div id="avatar_holder" style="background-image: url(<?php print $data['thumbnail']; ?>)"><span class="mw-icon-close"></span></div>
                            <span class='mw-ui-link' id="change_avatar">
          <?php _e("Change Image"); ?>
          </span>
                        <?php } ?>
                        <input type="hidden" class="mw-ui-field" name="thumbnail" id="user_thumbnail" value="<?php print $data['thumbnail']; ?>"></td>
                </tr>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -186,7 +186,8 @@
     </span>
             <?php endif; ?>
         </div>
-        <input type="hidden" class="mw-ui-field" name="id" value="<?php print $data['id']; ?>">
+        <input type="hidden"   name="id" value="<?php print $data['id']; ?>">
+        <input type="hidden"   name="token" value="<?php print csrf_token() ?>"  autocomplete="off">
         <div>
             <table btos="0" cellpadding="0" cellspacing="0" class="mw-ui-table mw-ui-table-basic mw-admin-user-tab-content" width="100%">
                 <col width="150px"/>
```
