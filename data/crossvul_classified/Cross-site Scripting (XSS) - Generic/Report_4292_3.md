# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4292_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4292_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 25-66 of the vulnerable file.

            <tr> 
                <th>Code</th>
                <th>Amount</th>
                <th>Valid from</th>
                <th>Valid to</th>
                <th>Status</th>
                <th></th>
            </tr>
        </thead>
        <tbody>
            <?php
            if (!empty($discountCodes)) {
                foreach ($discountCodes as $code) {
                    if ($code['status'] == 1) {
                        $tostatus = 0;
                    } else {
                        $tostatus = 1;
                    }
                    ?>
                    <tr> 
                        <td><?= $code['code'] ?></td>
                        <td><?= $code['type'] == 'float' ? '-' . $code['amount'] : '-' . $code['amount'] . '%' ?></td>
                        <td><?= date('d.m.Y', $code['valid_from_date']) ?></td>
                        <td <?= time() > $code['valid_to_date'] ? 'class="text-danger"' : '' ?>><?= date('d.m.Y', $code['valid_to_date']) ?></td>
                        <td class="text-center">
                            <a href="<?= base_url('admin/discounts?codeid=' . $code['id'] . '&tostatus=' . $tostatus) ?>">
                                <?= $code['status'] == 1 ? '<span class="label label-success">Enabled</span>' : '<span class="label label-danger">Disabled</span>' ?>
                            </a>
                        </td>
                        <td class="text-center">
                            <a href="<?= base_url('admin/discounts?edit=' . $code['id']) ?>" class="btn btn-primary btn-xs">Edit</a>
                        </td>
                    </tr> 
                    <?php
                }
            } else {
                ?>
                <tr>
                    <td colspan="6">No discount codes added</td> 
                </tr> 
            <?php } ?>
        </tbody>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,17 +42,17 @@
                     }
                     ?>
                     <tr> 
-                        <td><?= $code['code'] ?></td>
-                        <td><?= $code['type'] == 'float' ? '-' . $code['amount'] : '-' . $code['amount'] . '%' ?></td>
+                        <td><?= htmlspecialchars($code['code']) ?></td>
+                        <td><?= $code['type'] == 'float' ? '-' . htmlspecialchars($code['amount']) : '-' . htmlspecialchars($code['amount']) . '%' ?></td>
                         <td><?= date('d.m.Y', $code['valid_from_date']) ?></td>
                         <td <?= time() > $code['valid_to_date'] ? 'class="text-danger"' : '' ?>><?= date('d.m.Y', $code['valid_to_date']) ?></td>
                         <td class="text-center">
-                            <a href="<?= base_url('admin/discounts?codeid=' . $code['id'] . '&tostatus=' . $tostatus) ?>">
-                                <?= $code['status'] == 1 ? '<span class="label label-success">Enabled</span>' : '<span class="label label-danger">Disabled</span>' ?>
+                            <a href="<?= base_url('admin/discounts?codeid=' . (int)$code['id'] . '&tostatus=' . (int)$tostatus) ?>">
+                                <?= (int)$code['status'] == 1 ? '<span class="label label-success">Enabled</span>' : '<span class="label label-danger">Disabled</span>' ?>
                             </a>
                         </td>
                         <td class="text-center">
-                            <a href="<?= base_url('admin/discounts?edit=' . $code['id']) ?>" class="btn btn-primary btn-xs">Edit</a>
+                            <a href="<?= base_url('admin/discounts?edit=' . (int)$code['id']) ?>" class="btn btn-primary btn-xs">Edit</a>
                         </td>
                     </tr> 
                     <?php
@@ -72,7 +72,7 @@
     <div class="modal-dialog" role="document">
         <div class="modal-content">
             <form action="" method="POST">
-                <input type="hidden" name="update" value="<?= isset($_POST['update']) ? $_POST['update'] : '0' ?>">
+                <input type="hidden" name="update" value="<?= isset($_POST['update']) ? (int)$_POST['update'] : '0' ?>">
                 <div class="modal-header">
                     <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                     <h4 class="modal-title" id="myModalLabel">Add discount code</h4>
@@ -90,11 +90,11 @@
                     </div>
                     <div class="form-group">
                         <label>Discount value</label>
-                        <input class="form-control" name="amount" value="<?= isset($_POST['amount']) ? $_POST['amount'] : '' ?>" type="text">
+                        <input class="form-control" name="amount" value="<?= isset($_POST['amount']) ? htmlspecialchars($_POST['amount']) : '' ?>" type="text">
                     </div>
                     <div class="form-group" style="position: relative;">
                         <label>Discount code</label>
-                        <input class="form-control" name="code" value="<?= isset($_POST['code']) ? $_POST['code'] : '' ?>" type="text">
+                        <input class="form-control" name="code" value="<?= isset($_POST['code']) ? htmlspecialchars($_POST['code']) : '' ?>" type="text">
                         <div style="position: absolute; right:5px; top:30px;">
                             <input type="text" data-toggle="tooltip" title="Set length of code" data-placement="top" class="codeLength" value="6" style="border: 1px solid #dadada;float: left;height: 20px; margin-right: 4px; text-align: center; margin-top: 1px; width: 20px;">
                             <a href="javascript:void(0);" onclick="generateDiscountCode()" class="btn btn-xs btn-default">Generate</a>
@@ -102,11 +102,11 @@
                     </div>
                     <div class="form-group">
                         <label>Valid from date</label>
-                        <input class="form-control datepicker" name="valid_from_date" value="<?= isset($_POST['valid_from_date']) ? $_POST['valid_from_date'] : '' ?>" type="text">
+                        <input class="form-control datepicker" name="valid_from_date" value="<?= isset($_POST['valid_from_date']) ? htmlspecialchars($_POST['valid_from_date']) : '' ?>" type="text">
                     </div>
                     <div class="form-group">
                         <label>Valid to date</label>
-                        <input class="form-control datepicker" name="valid_to_date" value="<?= isset($_POST['valid_to_date']) ? $_POST['valid_to_date'] : '' ?>" type="text">
+                        <input class="form-control datepicker" name="valid_to_date" value="<?= isset($_POST['valid_to_date']) ? htmlspecialchars($_POST['valid_to_date']) : '' ?>" type="text">
                     </div>
                 </div>
                 <div class="modal-footer">
```
