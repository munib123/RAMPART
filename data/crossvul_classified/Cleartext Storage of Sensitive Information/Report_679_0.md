# CrossVul Fix Pair: Cleartext Storage of Sensitive Information in php
**Pair ID:** 679_0
**Vulnerability Class:** Cleartext Storage of Sensitive Information
**CWE:** CWE-312
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `679_0`)

## Vulnerability Information & PoC

## Description
Cleartext Storage of Sensitive Information - Because the information is stored in cleartext (i.

## Vulnerable Code
```php
Lines 3-43 of the vulnerable file.


if (class_exists("\\Illuminate\\Routing\\Controller")) {
    class BaseController extends \Illuminate\Routing\Controller {}
} else if (class_exists("Laravel\\Lumen\\Routing\\Controller")) {
    class BaseController extends \Laravel\Lumen\Routing\Controller {}
}

class LogViewerController extends BaseController
{
    protected $request;

    public function __construct ()
    {
        $this->request = app('request');
    }

    public function index()
    {

        if ($this->request->input('l')) {
            LaravelLogViewer::setFile(base64_decode($this->request->input('l')));
        }

        if ($this->request->input('dl')) {
            return $this->download(LaravelLogViewer::pathToLogFile(base64_decode($this->request->input('dl'))));
        } elseif ($this->request->has('del')) {
            app('files')->delete(LaravelLogViewer::pathToLogFile(base64_decode($this->request->input('del'))));
            return $this->redirect($this->request->url());
        } elseif ($this->request->has('delall')) {
            foreach(LaravelLogViewer::getFiles(true) as $file){
                app('files')->delete(LaravelLogViewer::pathToLogFile($file));
            }
            return $this->redirect($this->request->url());
        }
        
        $data = [
            'logs' => LaravelLogViewer::all(),
            'files' => LaravelLogViewer::getFiles(true),
            'current_file' => LaravelLogViewer::getFileName()
        ];

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,13 +20,13 @@
     {
 
         if ($this->request->input('l')) {
-            LaravelLogViewer::setFile(base64_decode($this->request->input('l')));
+            LaravelLogViewer::setFile(\Crypt::decrypt($this->request->input('l')));
         }
 
         if ($this->request->input('dl')) {
-            return $this->download(LaravelLogViewer::pathToLogFile(base64_decode($this->request->input('dl'))));
+            return $this->download(LaravelLogViewer::pathToLogFile(\Crypt::decrypt($this->request->input('dl'))));
         } elseif ($this->request->has('del')) {
-            app('files')->delete(LaravelLogViewer::pathToLogFile(base64_decode($this->request->input('del'))));
+            app('files')->delete(LaravelLogViewer::pathToLogFile(\Crypt::decrypt($this->request->input('del'))));
             return $this->redirect($this->request->url());
         } elseif ($this->request->has('delall')) {
             foreach(LaravelLogViewer::getFiles(true) as $file){
```
