# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5560_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5560_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 110-150 of the vulnerable file.

  # so that we can give Ganglia server a little breather from generating all those
  # images
  #####################################################################################
  if ( $current_hour >= $office_hour_min && $current_hour <= $office_hour_max ) {

  ?>

  <div style="position: fixed; left: 20; width: 800; top: 2; font-size: 30px;"><?php echo $title;  ?></div>
  <div style="position: fixed; left: 20; width: 600; top: 55; font-size: 20px;">Next: <?php echo $nexttitle  ?></div><br />

  <table>
  <tr>
    <td><img src="<?php echo $gangliapath . "&r=hour&z=${large_size}&" . $view_elements[$id]['graph_args']; ?>"><br />
	<img src="<?php echo $gangliapath . "&r=day&z=${large_size}&" . $view_elements[$id]['graph_args']; ?>"></td>
    <td valign="top">
      <img src="<?php echo $gangliapath . "&r=week&z=${small_size}&" . $view_elements[$id]['graph_args']; ?>">
      <img src="<?php echo $gangliapath . "&r=month&z=${small_size}&" . $view_elements[$id]['graph_args']; ?>">
    <div style="margin-top: 10px; font-size: 48px; text-align: center;"><?php echo date(DATE_RFC850); ?></div>
    <p>
    <center><form>
    <input type="hidden" name="view_name" value="<?php print $_GET['view_name'] ?>">
    <input type="hidden" name="id" value="<?php print $nextid ?>">
    Rotate graphs every <select onChange="form.submit();" name="timeout">
    <?php
      for ( $i = 10 ; $i <= 90 ; $i += 5 ) {
	if ( $timeout == $i )
	  $selected = "selected";
	else
	  $selected = "";
	print "<option value='" . $i . "' $selected>$i</option>";
      }
    ?>
    </select> seconds.</form></center>
    </p>
    <center><a href="/ganglia/">Go back to Ganglia</a></center></div>
	  </td>
  </tr>
  </table>
  <div>

  <?php
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -127,7 +127,7 @@
     <div style="margin-top: 10px; font-size: 48px; text-align: center;"><?php echo date(DATE_RFC850); ?></div>
     <p>
     <center><form>
-    <input type="hidden" name="view_name" value="<?php print $_GET['view_name'] ?>">
+    <input type="hidden" name="view_name" value="<?php print htmlspecialchars($_GET['view_name']) ?>">
     <input type="hidden" name="id" value="<?php print $nextid ?>">
     Rotate graphs every <select onChange="form.submit();" name="timeout">
     <?php
```
