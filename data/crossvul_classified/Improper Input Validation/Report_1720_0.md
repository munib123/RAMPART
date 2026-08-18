# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1720_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1720_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 10-50 of the vulnerable file.


/**
 * The FileManager allows users to upload and manipulate files.
 *
 * Note - Mostly rewritten since Wolf CMS 0.6.0
 *
 * @package Plugins
 * @subpackage file-manager
 *
 * @author Martijn van der Kleijn <martijn.niji@gmail.com>
 * @copyright Martijn van der Kleijn, 2008-2010
 * @license http://www.gnu.org/licenses/gpl.html GPLv3 license
 *
 * @todo Starting from PHP 5.3, use FileInfo
 */

/* Security measure */
if (!defined('IN_CMS')) { exit(); }

/**
 * 
 */
class FileManagerController extends PluginController {

    var $path;
    var $fullpath;

    public static function _checkPermission() {
        AuthUser::load();
        if (!AuthUser::isLoggedIn()) {
            redirect(get_url('login'));
        } else if (!AuthUser::hasPermission('file_manager_view')) {
            Flash::set('error', __('You do not have permission to access the requested page!'));
            redirect(get_url());
        }
    }

    public function __construct() {
        self::_checkPermission();

        $this->setLayout('backend');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 if (!defined('IN_CMS')) { exit(); }
 
 /**
- * 
+ *
  */
 class FileManagerController extends PluginController {
 
@@ -53,6 +53,14 @@
 
     public function index() {
         $this->browse();
+    }
+
+    static function htmlContextCleaner($input) {
+        $bad_chars = array("<", ">");
+        $safe_chars = array("&lt;", "&gt;");
+        $output = str_replace($bad_chars, $safe_chars, $input);
+
+        return stripslashes($output);
     }
 
     public function browse() {
@@ -94,7 +102,7 @@
         $this->fullpath = preg_replace('/\/\//', '/', $this->fullpath);
 
         $this->display('file_manager/views/index', array(
-            'dir' => $this->path,
+            'dir' => htmlContextCleaner($this->path),
             //'files' => $this->_getListFiles()
             'files' => $this->_listFiles()
         ));
@@ -133,15 +141,15 @@
 
         // We don't allow leading slashes
         $filename = preg_replace('/^\//', '', $filename);
-        
+
         // Check if file had URL_SUFFIX - if so, append it to filename
         $filename .= (isset($_GET['has_url_suffix']) && $_GET['has_url_suffix']==='1') ? URL_SUFFIX : '';
-        
+
         $file = FILES_DIR . '/' . $filename;
         if (!$this->_isImage($file) && file_exists($file)) {
             $content = file_get_contents($file);
         }
-        
+
         $this->display('file_manager/views/view', array(
             'csrf_token' => SecureToken::generateToken(BASE_URL.'plugin/file_manager/save/'.$filename),
             'is_image' => $this->_isImage($file),
@@ -156,7 +164,7 @@
         // security (remove all ..)
         $data['name'] = str_replace('..', '', $data['name']);
         $file = FILES_DIR . DS . $data['name'];
-        
+
         // CSRF checks
         if (isset($_POST['csrf_token'])) {
             $csrf_token = $_POST['csrf_token'];
@@ -169,7 +177,7 @@
             Flash::set('error', __('No CSRF token found!'));
             redirect(get_url('plugin/file_manager/view/'.$data['name']));
         }
-        
+
         if (file_exists($file)) {
             if (file_put_contents($file, $data['content']) !== false) {
                 Flash::set('success', __('File has been saved with success!'));
@@ -197,7 +205,7 @@
             Flash::set('error', __('You do not have sufficient permissions to create a file.'));
             redirect(get_url('plugin/file_manager/browse/'));
         }
-        
+
         // CSRF checks
         if (isset($_POST['csrf_token'])) {
             $csrf_token = $_POST['csrf_token'];
@@ -231,7 +239,7 @@
             Flash::set('error', __('You do not have sufficient permissions to create a directory.'));
             redirect(get_url('plugin/file_manager/browse/'));
         }
-        
+
         // CSRF checks
         if (isset($_POST['csrf_token'])) {
             $csrf_token = $_POST['csrf_token'];
@@ -269,7 +277,7 @@
         $paths = func_get_args();
 
         $file = urldecode(join('/', $paths));
-        
+
         // CSRF checks
         if (isset($_GET['csrf_token'])) {
             $csrf_token = $_GET['csrf_token'];
@@ -304,7 +312,7 @@
             Flash::set('error', __('You do not have sufficient permissions to upload a file.'));
             redirect(get_url('plugin/file_manager/browse/'));
         }
-        
+
         // CSRF checks
         if (isset($_POST['csrf_token'])) {
             $csrf_token = $_POST['csrf_token'];
@@ -317,7 +325,7 @@
             Flash::set('error', __('No CSRF token found!'));
             redirect(get_url('plugin/file_manager/browse/'));
         }
-        
+
         $mask = Plugin::getSetting('umask', 'file_manager');
         umask(octdec($mask));
 
@@ -328,6 +336,12 @@
         // Clean filenames
         $filename = preg_replace('/ /', '_', $_FILES['upload_file']['name']);
         $filename = preg_replace('/[^a-z0-9_\-\.]/i', '', $filename);
+
+        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
+        if (in_array($ext, ['php', 'php3', 'php4', 'inc'])) {
+            Flash::set('error', __('Not allowed to upload files with extension :ext', $ext));
+            redirect(get_url('plugin/file_manager/browse/'));
+        }
 
         if (isset($_FILES)) {
             $file = $this->_upload_file($filename, FILES_DIR . '/' . $path . '/', $_FILES['upload_file']['tmp_name'], $overwrite);
@@ -356,7 +370,7 @@
             Flash::set('error', __('No CSRF token found!'));
             redirect(get_url('plugin/file_manager/browse/'));
         }
-        
+
         $data = $_POST['file'];
         $data['name'] = str_replace('..', '', $data['name']);
         $file = FILES_DIR . '/' . $data['name'];
@@ -378,7 +392,7 @@
             Flash::set('error', __('You do not have sufficient permissions to rename this file or directory.'));
             redirect(get_url('plugin/file_manager/browse/'));
         }
-        
+
         // CSRF checks
         if (isset($_POST['csrf_token'])) {
             $csrf_token = $_POST['csrf_token'];
@@ -404,6 +418,14 @@
         $path = substr($data['current_name'], 0, strrpos($data['current_name'], '/'));
         $file = FILES_DIR . '/' . $data['current_name'];
 
+        // Check if trying to rename to php file (.php / .php3 etc)
+        $ext = strtolower(pathinfo($data['new_name'], PATHINFO_EXTENSION));
+
+        if (in_array($ext, ['php', 'php3', 'php4', 'inc'])) {
+            Flash::set('error', __('Not allowed to rename to :ext', $ext));
+            redirect(get_url('plugin/file_manager/browse/' . $path));
+        }
+
         // Check another file doesn't already exist with same name
         if (file_exists(FILES_DIR . '/' . $path . '/' . $data['new_name'])) {
             Flash::set('error', __('A file or directory with that name already exists!'));
@@ -442,7 +464,7 @@
                 $name = $cur->getFilename();
                 if (Plugin::getSetting('show_hidden', 'file_manager') == '0' && $name[0] === '.')
                     continue;
-                
+
                 if (Plugin::getSetting('show_backups', 'file_manager') == '0' && $name[strlen($name)-1] === '~')
                     continue;
 
@@ -453,7 +475,7 @@
                 $object->size = convert_size($cur->getSize());
                 $object->mtime = date('D, j M, Y', $cur->getMTime());
                 list($object->perms, $object->chmod) = $this->_getPermissions($cur->getPerms());
-                
+
                 // Find the file type
                 $object->type = $this->_getFileType($cur);
 
@@ -477,13 +499,13 @@
                     return strnatcmp($a->name, $b->name);
                 }
             });
-            
+
             return $files;
         }
 
         return array();
     }
-    
+
     private function _getFileType($file) {
         $default = 'unknown';
 
@@ -659,7 +681,7 @@
             Flash::set('error', __('You do not have permission to access the requested page!'));
             redirect(get_url());
         }
-        
+
         $settings = Plugin::getAllSettings('file_manager');
 
         if (!$settings) {
@@ -678,7 +700,7 @@
             Flash::set('error', __('You do not have permission to access the requested page!'));
             redirect(get_url());
         }
-        
+
         if (!isset($_POST['settings'])) {
             Flash::set('error', 'File Manager - ' . __('form was not posted.'));
             redirect(get_url('plugin/file_manager/settings'));
```
