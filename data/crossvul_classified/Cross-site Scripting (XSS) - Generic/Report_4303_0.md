# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4303_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4303_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 130-170 of the vulnerable file.

                            <div id="sent-date-container" class="date-container"  <?php if (!$bCompletedValue):?>style="display: none;"<?php endif; ?>>
                            <div id="completed-date_datetimepicker" class="input-group date">
                                <input class="YesNoDatePicker form-control" id="completed-date" type="text" value="<?php echo isset($completed) ? $completed : ''?>" name="completed-date" data-date-format="<?php echo $dateformatdetails['jsdate']; ?> HH:mm">
                                <span class="input-group-addon"><span class="fa fa-calendar"></span></span>
                            </div>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                    <input class='form-control hidden YesNoDateHidden' type='text' size='20' id='completed' name='completed' value="<?php if (isset($completed)) {echo $completed; } else {echo " N "; }?>" />
                </div>

            </div>

            <!-- First name, Last name -->            
            <div class="form-group">
                <label class=" control-label" for='firstname'>
                <?php eT("First name:"); ?>
                </label>
                <div class="">
                <input class='form-control' type='text' size='30' id='firstname' name='firstname' value="<?php if (isset($firstname)) {echo $firstname; } ?>" />
                </div>
            </div>
            <div class="form-group">
                <label class=" control-label" for='lastname'>
                <?php eT("Last name:"); ?>
                </label>
                <div class="">
                <input class='form-control' type='text' size='30' id='lastname' name='lastname' value="<?php if (isset($lastname)) {echo $lastname; } ?>" />
                </div>
            </div>


            <!-- Token, language -->
            <div class="form-group">
                <label class=" control-label" for='token'>
                <?php eT("Token:"); ?>
                </label>
                <div class="">
                <input class='form-control' type='text' maxlength="<?php echo $iTokenLength; ?>" size='20' name='token' id='token' value="<?php if (isset($token)) {echo $token; } ?>" />
                <?php if ($token_subaction == "addnew"): ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -147,7 +147,10 @@
                 <?php eT("First name:"); ?>
                 </label>
                 <div class="">
-                <input class='form-control' type='text' size='30' id='firstname' name='firstname' value="<?php if (isset($firstname)) {echo $firstname; } ?>" />
+                    <?=TbHtml::textField('firstname', $firstname, [
+                        'class' => 'form-control',
+                        'size' => '30',
+                    ]);?>
                 </div>
             </div>
             <div class="form-group">
@@ -155,7 +158,10 @@
                 <?php eT("Last name:"); ?>
                 </label>
                 <div class="">
-                <input class='form-control' type='text' size='30' id='lastname' name='lastname' value="<?php if (isset($lastname)) {echo $lastname; } ?>" />
+                    <?=TbHtml::textField('lastname', $lastname, [
+                        'class' => 'form-control',
+                        'size' => '30',
+                    ]);?>
                 </div>
             </div>
 
@@ -189,7 +195,11 @@
                 <?php eT("Email:"); ?>
             </label>
             <div class="">
-                <input class='form-control' type='text' maxlength='320' size='50' id='email' name='email' value="<?php if (isset($email)) {echo $email; } ?>" />
+                <?=TbHtml::emailField('email', $email, [
+                        'class' => 'form-control',
+                        'size' => '50',
+                        'maxlength' => '320' 
+                ]);?>
             </div>
             </div>
 
@@ -199,7 +209,12 @@
                 <?php eT("Email status:"); ?>
             </label>
             <div class="">
-                <input class='form-control' type='text' maxlength='320' size='50' id='emailstatus' name='emailstatus' placeholder='OK' value="<?php if (isset($emailstatus)) {echo $emailstatus; } else {echo " OK "; }?>" />
+                <?=TbHtml::textField('emailstatus', $emailstatus, [
+                        'class' => 'form-control',
+                        'size' => '50',
+                        'maxlength' => '320',
+                        'placeholder' => 'OK'
+                ]);?>
             </div>
             </div>
 
```
