# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2881_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2881_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 80-122 of the vulnerable file.

                '<a class="close" data-dismiss="alert" href="#">&times;</a>',
                $PMF_LANG['ad_entryins_fail'],
                $faqConfig->getDb()->error()
            );
        }
    }
    ?>
    <table class="table">
        <thead>
        <tr>
            <th>#</th>
            <th><?php echo $PMF_LANG['ad_instance_url'] ?></th>
            <th><?php echo $PMF_LANG['ad_instance_path'] ?></th>
            <th colspan="3"><?php echo $PMF_LANG['ad_instance_name'] ?></th>
        </tr>
        </thead>
        <tbody>
        <?php
        foreach ($instance->getAllInstances() as $site):
            $currentInstance = new PMF_Instance($faqConfig);
    $currentInstance->getInstanceById($site->id);
    $currentInstance->setId($site->id);
    ?>
        <tr id="row-instance-<?php print $site->id ?>">
            <td><?php print $site->id ?></td>
            <td><a href="<?php print $site->url.$site->instance ?>"><?php print $site->url ?></a></td>
            <td><?php print $site->instance ?></td>
            <td><?php print $site->comment ?></td>
            <td>
                <a href="?action=editinstance&instance_id=<?php print $site->id ?>" class="btn btn-info">
                    <i aria-hidden="true" class="fa fa-pencil"></i>
                </a>
            </td>
            <td>
                <?php if ($currentInstance->getConfig('isMaster') !== true): ?>
                <a href="javascript:;" id="delete-instance-<?php print $site->id ?>"
                   class="btn btn-danger pmf-instance-delete"
                   data-csrf-token="<?php echo $user->getCsrfTokenFromSession() ?>">
                    <i aria-hidden="true" class="fa fa-trash"></i>
                </a>
                <?php endif;
    ?>
            </td>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,9 +97,9 @@
         <?php
         foreach ($instance->getAllInstances() as $site):
             $currentInstance = new PMF_Instance($faqConfig);
-    $currentInstance->getInstanceById($site->id);
-    $currentInstance->setId($site->id);
-    ?>
+            $currentInstance->getInstanceById($site->id);
+            $currentInstance->setId($site->id);
+            ?>
         <tr id="row-instance-<?php print $site->id ?>">
             <td><?php print $site->id ?></td>
             <td><a href="<?php print $site->url.$site->instance ?>"><?php print $site->url ?></a></td>
@@ -117,12 +117,10 @@
                    data-csrf-token="<?php echo $user->getCsrfTokenFromSession() ?>">
                     <i aria-hidden="true" class="fa fa-trash"></i>
                 </a>
-                <?php endif;
-    ?>
+                <?php endif; ?>
             </td>
         </tr>
-        <?php endforeach;
-    ?>
+        <?php endforeach; ?>
         </tbody>
     </table>
 
@@ -135,6 +133,7 @@
                 </div>
                 <div class="modal-body">
                     <form class="form-horizontal" action="#" method="post" accept-charset="utf-8">
+                        <input type="hidden" name="csrf" id="csrf" value="<?php echo $user->getCsrfTokenFromSession() ?>">
                         <div class="form-group">
                             <label class="control-label col-lg-4">
                                 <?php echo $PMF_LANG['ad_instance_url'] ?>:
@@ -205,6 +204,7 @@
             // Add instance
             $('.pmf-instance-add').click(function(event) {
                 event.preventDefault();
+                var csrf     = $('#csrf').val();
                 var url      = $('#url').val();
                 var instance = $('#instance').val();
                 var comment  = $('#comment').val();
@@ -213,8 +213,9 @@
                 var password = $('#password').val();
 
                 $.get('index.php',
-                    { action: 'ajax', ajax: 'config', ajaxaction: 'add_instance',
-                        url: url, instance: instance, comment: comment, email: email, admin: admin, password: password
+                    {
+                        action: 'ajax', ajax: 'config', ajaxaction: 'add_instance', csrf: csrf, url: url,
+                        instance: instance, comment: comment, email: email, admin: admin, password: password
                     },
                     function(data) {
                         if (typeof(data.added) === 'undefined') {
```
