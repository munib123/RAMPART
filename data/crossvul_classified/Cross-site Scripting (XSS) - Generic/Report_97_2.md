# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 97_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `97_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php
/**
 * This the first of two pages to support posting of EOBs.
 * The second is sl_eob_invoice.php.
 * Windows compatibility and statement downloading:
 *      2009 Bill Cernansky and Tony McCormick [mi-squared.com]
 *
 * Copyright (C) 2005-2010 Rod Roark <rod@sunsetsystems.com>
 *
 * LICENSE: This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://opensource.org/licenses/gpl-license.php>;.
 *
 * @package OpenEMR
 * @author  Rod Roark <rod@sunsetsystems.com>
 * @author  Roberto Vasquez <robertogagliotta@gmail.com>
 * @author  Jerry Padgett <sjpadgett@gmail.com>
 * @link    http://www.open-emr.org
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,28 +2,21 @@
 /**
  * This the first of two pages to support posting of EOBs.
  * The second is sl_eob_invoice.php.
- * Windows compatibility and statement downloading:
- *      2009 Bill Cernansky and Tony McCormick [mi-squared.com]
  *
- * Copyright (C) 2005-2010 Rod Roark <rod@sunsetsystems.com>
- *
- * LICENSE: This program is free software; you can redistribute it and/or
- * modify it under the terms of the GNU General Public License
- * as published by the Free Software Foundation; either version 2
- * of the License, or (at your option) any later version.
- * This program is distributed in the hope that it will be useful,
- * but WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
- * GNU General Public License for more details.
- * You should have received a copy of the GNU General Public License
- * along with this program. If not, see <http://opensource.org/licenses/gpl-license.php>;.
- *
- * @package OpenEMR
- * @author  Rod Roark <rod@sunsetsystems.com>
- * @author  Roberto Vasquez <robertogagliotta@gmail.com>
- * @author  Jerry Padgett <sjpadgett@gmail.com>
- * @link    http://www.open-emr.org
+ * @package   OpenEMR
+ * @link      http://www.open-emr.org
+ * @author    Rod Roark <rod@sunsetsystems.com>
+ * @author    Bill Cernansky
+ * @author    Tony McCormick
+ * @author    Roberto Vasquez <robertogagliotta@gmail.com>
+ * @author    Jerry Padgett <sjpadgett@gmail.com>
+ * @author    Brady Miller <brady.g.miller@gmail.com>
+ * @copyright Copyright (c) 2005-2010 Rod Roark <rod@sunsetsystems.com>
+ * @copyright Copyright (c) 2018 Brady Miller <brady.g.miller@gmail.com>
+ * @license   https://github.com/openemr/openemr/blob/master/LICENSE GNU General Public License 3
  */
+
+
 require_once("../globals.php");
 require_once("$srcdir/patient.inc");
 require_once("$srcdir/invoice_summary.inc.php");
@@ -642,14 +635,14 @@
             <?php xl('Source:', 'e'); ?>
        </td>
        <td>
-         <input type='text' name='form_source' size='10' value='<?php echo $_POST['form_source']; ?>'
+         <input type='text' name='form_source' size='10' value='<?php echo attr($_POST['form_source']); ?>'
          title='<?php xl("A check number or claim number to identify the payment", "e"); ?>'>
        </td>
        <td>
             <?php xl('Pay Date:', 'e'); ?>
        </td>
        <td>
-         <input type='text' name='form_paydate' size='10' value='<?php echo $_POST['form_paydate']; ?>'
+         <input type='text' name='form_paydate' size='10' value='<?php echo attr($_POST['form_paydate']); ?>'
          onkeyup='datekeyup(this,mypcc)' onblur='dateblur(this,mypcc)'
          title='<?php xl("Date of payment yyyy-mm-dd", "e"); ?>'>
        </td>
@@ -658,7 +651,7 @@
             <?php xl('Deposit Date:', 'e'); ?>
        </td>
        <td>
-         <input type='text' name='form_deposit_date' size='10' value='<?php echo $_POST['form_deposit_date']; ?>'
+         <input type='text' name='form_deposit_date' size='10' value='<?php echo attr($_POST['form_deposit_date']); ?>'
          onkeyup='datekeyup(this,mypcc)' onblur='dateblur(this,mypcc)'
          title='<?php xl("Date of bank deposit yyyy-mm-dd", "e"); ?>'>
        </td>
@@ -667,7 +660,7 @@
             <?php xl('Amount:', 'e'); ?>
        </td>
        <td>
-         <input type='text' name='form_amount' size='10' value='<?php echo $_POST['form_amount']; ?>'
+         <input type='text' name='form_amount' size='10' value='<?php echo attr($_POST['form_amount']); ?>'
          title='<?php xl("Paid amount that you will allocate", "e"); ?>'>
        </td>
        <td align='right'>
@@ -684,35 +677,35 @@
         <?php xl('Name:', 'e'); ?>
      </td>
      <td>
-       <input type='text' name='form_name' size='10' value='<?php echo $_POST['form_name']; ?>'
+       <input type='text' name='form_name' size='10' value='<?php echo attr($_POST['form_name']); ?>'
        title='<?php xl("Any part of the patient name, or \"last,first\", or \"X-Y\"", "e"); ?>'>
      </td>
      <td>
         <?php xl('Chart ID:', 'e'); ?>
      </td>
      <td>
-       <input type='text' name='form_pid' size='10' value='<?php echo $_POST['form_pid']; ?>'
+       <input type='text' name='form_pid' size='10' value='<?php echo attr($_POST['form_pid']); ?>'
        title='<?php xl("Patient chart ID", "e"); ?>'>
      </td>
      <td>
         <?php xl('Encounter:', 'e'); ?>
      </td>
      <td>
-       <input type='text' name='form_encounter' size='10' value='<?php echo $_POST['form_encounter']; ?>'
+       <input type='text' name='form_encounter' size='10' value='<?php echo attr($_POST['form_encounter']); ?>'
        title='<?php xl("Encounter number", "e"); ?>'>
      </td>
      <td>
         <?php xl('Svc Date:', 'e'); ?>
      </td>
      <td>
-       <input type='text' name='form_date' size='10' value='<?php echo $_POST['form_date']; ?>'
+       <input type='text' name='form_date' size='10' value='<?php echo attr($_POST['form_date']); ?>'
        title='<?php xl("Date of service mm/dd/yyyy", "e"); ?>'>
      </td>
      <td>
         <?php xl('To:', 'e'); ?>
      </td>
      <td>
-       <input type='text' name='form_to_date' size='10' value='<?php echo $_POST['form_to_date']; ?>'
+       <input type='text' name='form_to_date' size='10' value='<?php echo attr($_POST['form_to_date']); ?>'
        title='<?php xl("Ending DOS mm/dd/yyyy if you wish to enter a range", "e"); ?>'>
      </td>
      <td>
```
