# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 286_2
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `286_2`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 175-215 of the vulnerable file.

    echo '<input type="radio" name="notif_choice" id="notif_choice" value="DEFAULT" '.$default.' onclick="hide(\'notif_perso\', \'default_mail\', \'perso_mail\')" />'.$l->g(488).'</br>
          <input type="radio" name="notif_choice" id="notif_choice" value="PERSO" '.$perso.' onclick="show(\'notif_perso\', \'default_mail\', \'perso_mail\')"/>'.$l->g(8012).'
          <div id ="notif_perso" '.$style_perso.' align="center"></br></br>';
    msg_warning($l->g(8016));
    echo '<input type="file" id="template" name="template"/>
          </div>';

    echo "<hr><h4> Preview </h4>";
    echo '<div class="col-md-8 col-xs-offset-0 col-md-offset-2">';

    //Default
    echo "<div id=default_mail ".$style_default.">";
    echo "<div class='form-group'><label class='control-label col-sm-2' for='subject'>".$l->g(8018)."</label><div class='col-sm-8'>
          <input type='text' class='form-control' id='subject' name='subject' size='50' maxlength='255' value='".$l->g(8019)."' disabled/></div></div>";
    $output = $mail->replace_value('require/mail/Templates/OCS_template.html', 'DEFAULT');
    echo $output;
    echo "</div>";

    //Perso
    $info = $mail->get_all_information('PERSO');
    echo "<div id=perso_mail ".$style_perso.">";
    echo "<div class='form-group'><label class='control-label col-sm-2' for='subject'>".$l->g(8018)."</label><div class='col-sm-8'>
          <input type='text' class='form-control' id='subject' name='subject' size='50' maxlength='255' value='".$info['PERSO']['SUBJECT']."'/></div></div>";
    $output = $mail->replace_value($mail->get_template_perso(), 'PERSO');
    echo $output;
    echo "</div>";


    echo "</br></br>";

    ?>

    <input type='hidden' id='RELOAD_CONF' name='RELOAD_CONF' value=''>
    <input type="submit" name="Send" value="<?php echo $l->g(103) ?>" class="btn btn-success">
    <input type="submit" name="Reset" value="<?php echo $l->g(1364) ?>" class="btn btn-danger">

    <?php
    echo "</div>";
}

echo "</div>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -192,10 +192,13 @@
 
     //Perso
     $info = $mail->get_all_information('PERSO');
+    $output = $mail->replace_value($mail->get_template_perso(), 'PERSO');
+    if(!$output){
+        $output = $l->g(8020);
+    }
     echo "<div id=perso_mail ".$style_perso.">";
     echo "<div class='form-group'><label class='control-label col-sm-2' for='subject'>".$l->g(8018)."</label><div class='col-sm-8'>
           <input type='text' class='form-control' id='subject' name='subject' size='50' maxlength='255' value='".$info['PERSO']['SUBJECT']."'/></div></div>";
-    $output = $mail->replace_value($mail->get_template_perso(), 'PERSO');
     echo $output;
     echo "</div>";
 
```
