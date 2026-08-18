# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 387_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `387_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 332-372 of the vulnerable file.

                            <?php if ($GLOBALS['portal_two_pass_reset'] && isset($_GET['w']) && (isset($_GET['u']) || isset($_GET['p']))) { ?>
                               <button class="btn btn-danger" onclick="location.replace('./index.php?requestNew=1')" style="margin-left:10px"><?php echo xlt('Reset Credentials');?></button>
                            <?php } ?>
                                <button  class="btn btn-success pull-right" type="submit" ><?php echo xlt('Log In');?></button>
                        </div>
                    </fieldset>
                </div>
          </div>
            <?php if (!(empty($hiddenLanguageField))) {
                echo $hiddenLanguageField; } ?>
    </form>
    </div><!-- div wrapper -->
    <?php } ?> <!--  logon wrapper -->
</div><!-- container -->

<script type="text/javascript">
$(document).ready(function() {

<?php // if something went wrong
if (isset($_GET['requestNew'])) {
    $_SESSION['patient_portal_onsite_two'] = true;
    $_SESSION['authUser'] = 'portal-user';
    $_SESSION['pid'] = true;
    ?>
    $('.datepicker').datetimepicker({
        <?php $datetimepicker_timepicker = false; ?>
        <?php $datetimepicker_showseconds = false; ?>
        <?php $datetimepicker_formatInput = false; ?>
        <?php require($GLOBALS['srcdir'] . '/js/xl/jquery-datetimepicker-2-5-4.js.php'); ?>
     });
    $(document.body).on('hidden.bs.modal', function () {
        callServer('cleanup');
    });
    $("#submitRequest").click(function () {
        callServer('is_new', '');
    });
<?php } ?>
<?php if (isset($_GET['w'])) { ?>
    var unique_id = $.gritter.add({
        title: '<span class="red"><?php echo xlt('Oops!');?></span>',
        text: '<?php echo xlt('Something went wrong. Please try again.'); ?>',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -349,7 +349,7 @@
 
 <?php // if something went wrong
 if (isset($_GET['requestNew'])) {
-    $_SESSION['patient_portal_onsite_two'] = true;
+    $_SESSION['register'] = true;
     $_SESSION['authUser'] = 'portal-user';
     $_SESSION['pid'] = true;
     ?>
```
