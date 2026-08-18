# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 286_3
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `286_3`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 31-71 of the vulnerable file.

 require PHPMAILER.'/PHPMailer.php';
 require PHPMAILER.'/SMTP.php';
 require __DIR__.'/../softwares/SoftwareCategory.php';
 require __DIR__.'/../assets/AssetsCategory.php';

 /**
  * Class for the notification mail
  */
 class NotificationMail
 {
      public $info = [];
      public $notif;
      public $div = [];
      private $champs = array('NOTIF_FOLLOW'=>'NOTIF_FOLLOW','NOTIF_MAIL_ADMIN'=>'NOTIF_MAIL_ADMIN','NOTIF_NAME_ADMIN'=>'NOTIF_NAME_ADMIN','NOTIF_MAIL_REPLY'=>'NOTIF_MAIL_REPLY',
                          'NOTIF_NAME_REPLY'=>'NOTIF_NAME_REPLY','NOTIF_SEND_MODE'=>'NOTIF_SEND_MODE','NOTIF_SMTP_HOST'=>'NOTIF_SMTP_HOST',
                          'NOTIF_PORT_SMTP'=>'NOTIF_PORT_SMTP','NOTIF_USER_SMTP'=>'NOTIF_USER_SMTP','NOTIF_PASSWD_SMTP'=>'NOTIF_PASSWD_SMTP',
                          'NOTIF_PROG_TIME'=>'NOTIF_PROG_TIME','NOTIF_PROG_DAY'=>'NOTIF_PROG_DAY'
                        );
      private $week = array('MON' => 'MON', 'TUE' => 'TUE', 'WED' => 'WED', 'THURS' => 'THURS', 'FRI' => 'FRI', 'SAT' => 'SAT', 'SUN' => 'SUN');

      public function __construct($language){
        global $l;
        $l = new language($language);
      }

      /**
       * Get the notification selected
       * @return [type] [description]
       */
      public function get_notif_selected(){
          $sql = "SELECT `FILE` FROM notification WHERE `TYPE`= 'SELECTED'";
          $result = mysqli_query($_SESSION['OCS']["readServer"], $sql);
          $item_notif = mysqli_fetch_array($result);

          return $item_notif['FILE'];
      }

      /**
       * Update the selected notification
       * @param  string $selected [description]
       */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,8 @@
                         );
       private $week = array('MON' => 'MON', 'TUE' => 'TUE', 'WED' => 'WED', 'THURS' => 'THURS', 'FRI' => 'FRI', 'SAT' => 'SAT', 'SUN' => 'SUN');
 
+      const HTML_EXT = 'html';
+      
       public function __construct($language){
         global $l;
         $l = new language($language);
@@ -180,20 +182,27 @@
        * @return void
        */
      public function send_notification($subject, $body, $altBody = '', $selected, $isHtml = false ){
-          $body = $this->replace_value($body, $selected);
-          try{
-             // Content
-             $this->notif->isHTML(false);
-             $this->notif->Subject = $subject;
-             $this->notif->Body    = $body;
-             $this->notif->AltBody = $altBody;
-
-             $this->notif->send();
-             error_log('Message has been sent');
-         } catch (Exception $e) {
-             $msg = 'Message could not be sent. Mailer Error: '. $mail->ErrorInfo;
-             error_log($msg);
-         }
+            
+            $body = $this->replace_value($body, $selected);
+         
+            if(!$body){
+                error_log('Error reading custom template');
+                return false;
+            }
+            
+            try{
+               // Content
+               $this->notif->isHTML(false);
+               $this->notif->Subject = $subject;
+               $this->notif->Body    = $body;
+               $this->notif->AltBody = $altBody;
+
+               $this->notif->send();
+               error_log('Message has been sent');
+           } catch (Exception $e) {
+               $msg = 'Message could not be sent. Mailer Error: '. $mail->ErrorInfo;
+               error_log($msg);
+           }
       }
 
       /**
@@ -214,7 +223,11 @@
           if($selected == 'DEFAULT'){
             $template = file_get_contents(TEMPLATE.'OCS_template.html', true);
           }else{
-            $template = file_get_contents($file, true);
+            if(file_exists($file)){
+                $template = file_get_contents($file, true); 
+            }else{
+                return false;
+            }
           }
 
           if(strpos($template, "{{") !== false){
@@ -263,6 +276,11 @@
       public function upload_file($file, $subject){
           global $l;
           $uploadFile = TEMPLATE . basename($file['template']['name']);
+          
+          if(!$this->is_html_extension($uploadFile)){
+              msg_error($l->g(8021));
+              return false;
+          }
 
           if($file['template']['type'] == 'text/html'){
             if (move_uploaded_file($_FILES['template']['tmp_name'], $uploadFile)) {
@@ -278,6 +296,22 @@
           }else{
             msg_error($l->g(8017));
             return false;
+          }
+      }
+      
+      /**
+       * Check if file respect naming convention
+       * And have extension .html
+       * 
+       * @param array $uploaded_file
+       */
+      private function is_html_extension($uploaded_file_name){
+          $ext = end((explode(".", $uploaded_file_name)));
+          var_dump($ext);
+          if($ext == self::HTML_EXT){
+              return true;
+          }else{
+              return false;
           }
       }
 
```
