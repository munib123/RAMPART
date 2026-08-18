# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 827_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `827_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 13-57 of the vulnerable file.

 * @author         Mike Nelson
 * @since         $VID:$
 *
 */
class RestApiDetector
{
    protected $site;
    protected $name;
    protected $description;
    protected $rest_api_url;
    protected $local;
    protected $initialized = false;

    /**
     * RestApiDetector constructor.
     * @param $site
     * @throws RestApiDetectorError
     */
    public function __construct($site)
    {
        // If the REST API Proxy Plugin isn't active, always use the current site.
        if(! PMB_REST_PROXY_EXISTS){
            $site = '';
        }
        $this->setSite($site);
        $this->getSiteInfo();
    }

    /**
     * Gets the site name and URL (works if they provide the "site" query param too,
     * being the URL, including schema, of a self-hosted or WordPress.com site)
     * @since $VID:$
     * @throws RestApiDetectorError
     */
    public function getSiteInfo()
    {
        // check for a site request param
        if(empty($this->getSite())){
            $this->setName(get_bloginfo('name'));
            $this->setDescription(get_bloginfo('description'));
            $this->setRestApiUrl(get_rest_url());
            $this->setSite(get_bloginfo('url'));
            $this->setLocal(true);
            return;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,11 +30,7 @@
      */
     public function __construct($site)
     {
-        // If the REST API Proxy Plugin isn't active, always use the current site.
-        if(! PMB_REST_PROXY_EXISTS){
-            $site = '';
-        }
-        $this->setSite($site);
+        $this->setSite($this->sanitizeSite($site));
         $this->getSiteInfo();
     }
 
@@ -55,14 +51,7 @@
             $this->setLocal(true);
             return;
         }
-        // If they forgot to add http(s), add it for them.
-        if(strpos($this->getSite(), 'http://') === false && strpos($this->getSite(), 'https://') === false) {
-            $this->setSite( 'http://' . $this->getSite());
-        }
-        // if there is one, check if it exists in wordpress.com, eg "retirementreflections.com"
-        $site = trailingslashit(sanitize_text_field($this->getSite()));
-
-
+        $site = $this->getSite();
         // Let's see if it's self-hosted...
         $data = $this->getSelfHostedSiteInfo($site);
 //        if($data === false){
@@ -75,6 +64,32 @@
         }
 
         return $data;
+    }
+
+    /**
+     * Avoid SSRF by sanitizing the site received.
+     * @since $VID:$
+     * @param $site
+     * @return mixed|string
+     */
+    protected function sanitizeSite($site)
+    {
+        // If the REST API Proxy Plugin isn't active, always use the current site.
+        if(! PMB_REST_PROXY_EXISTS){
+            return '';
+        }
+        // If they forgot to add http(s), add it for them.
+        if(strpos($site, 'http://') === false && strpos($site, 'https://') === false) {
+            $site = 'http://' . $site;
+        }
+        // if there is one, check if it exists in wordpress.com, eg "retirementreflections.com"
+
+        $file_info = pathinfo($site);
+        if( isset($file_info['extension'])){
+            $site = str_replace($file_info['filename'] . "." . $file_info['extension'], "", $site);
+        }
+        $site = trailingslashit(sanitize_text_field($site));
+        return $site;
     }
 
     /**
```
