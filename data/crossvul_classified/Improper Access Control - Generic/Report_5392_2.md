# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5392_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5392_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 492-533 of the vulnerable file.

        return preg_replace('/\r\n/', ' ', trim($val));
    }

    /**
     * Convert email html content to text
     * Remove scripts, styles, tags, and convert <br> to newline
     *
     * @param $val
     * @return mixed
     */
    public static function html2text($val) {
        $val = preg_replace('/(<script[^>]*>.+?<\/script>|<style[^>]*>.+?<\/style>)/s', '', $val); // remove any script or style blocks
        $val = trim(strip_tags(str_replace(array("<br />", "<br>", "br/>"), "\n", $val)));  // replace breaks with newlines
        return $val;
    }

    /**
     * Scrub input string for possible security issues.
     *
     * @static
     * @param $data string
     * @return string
     */
    public static function sanitize(&$data) {
//        return $data;

        if (is_array($data)) {
            $saved_params = array();
            if (!empty($data['controller']) && $data['controller'] == 'snippet') {
                $saved_params['body'] = $data['body'];  // store snippet body
            }
            foreach ($data as $var=>$val) {
//                $data[$var] = self::sanitize($val);
                $data[$var] = self::xss_clean($val);
            }
            if (!empty($saved_params)) {
                $data = array_merge($data, $saved_params);  // add stored snippet body
            }
        } else {
            if (empty($data)) {
                return $data;
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -509,8 +509,8 @@
      * Scrub input string for possible security issues.
      *
      * @static
-     * @param $data string
-     * @return string
+     * @param $data string|array
+     * @return string|array
      */
     public static function sanitize(&$data) {
 //        return $data;
```
