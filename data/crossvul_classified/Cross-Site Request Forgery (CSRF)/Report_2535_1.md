# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2535_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2535_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 17-61 of the vulnerable file.

       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

require_once("util.inc");
require_once("config.inc");

/* THIS MUST BE ABOVE ALL OTHER CODE */
if (empty($nocsrf)) {
    function csrf_startup()
    {
      csrf_conf('rewrite-js', '/csrf/csrf-magic.js');
      $timeout_minutes = isset($config['system']['webgui']['session_timeout']) ?  $config['system']['webgui']['session_timeout'] : 240;
      csrf_conf('expires', $timeout_minutes * 60);
    }
    require_once('csrf/csrf-magic.php');

    // make sure the session is closed after executing csrf-magic
    if (session_status() != PHP_SESSION_NONE) {
        session_write_close();
    }
}

function set_language()
{
    global $config;

    $lang = 'en_US';
    if (!empty($config['system']['language'])) {
        $lang = $config['system']['language'];
    }

    $lang_encoding = $lang . '.UTF-8';
    $textdomain = 'OPNsense';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,18 +34,17 @@
 
 /* THIS MUST BE ABOVE ALL OTHER CODE */
 if (empty($nocsrf)) {
-    function csrf_startup()
-    {
-      csrf_conf('rewrite-js', '/csrf/csrf-magic.js');
-      $timeout_minutes = isset($config['system']['webgui']['session_timeout']) ?  $config['system']['webgui']['session_timeout'] : 240;
-      csrf_conf('expires', $timeout_minutes * 60);
-    }
+    function csrf_startup() {
+        global $config;
+
+        csrf_conf('rewrite-js', '/csrf/csrf-magic.js');
+        $timeout_minutes = isset($config['system']['webgui']['session_timeout']) ? $config['system']['webgui']['session_timeout'] : 240;
+        csrf_conf('expires', $timeout_minutes * 60);
+    }
+
+    session_start();
     require_once('csrf/csrf-magic.php');
-
-    // make sure the session is closed after executing csrf-magic
-    if (session_status() != PHP_SESSION_NONE) {
-        session_write_close();
-    }
+    session_write_close();
 }
 
 function set_language()
```
