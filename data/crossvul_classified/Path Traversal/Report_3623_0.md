# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3623_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3623_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 13-53 of the vulnerable file.

     * the following conditions:
     * 
     * The above copyright notice and this permission notice shall be
     * included in all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
     * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
     * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
     * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
     * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
     * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
     * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
     */

    $cache    = true;
    $cachedir = '../../uploads';
    $base     = dirname(__FILE__);

    $type     = $_GET['type'];
    $elements = explode(',', $_GET['files']);

    // Determine last modification date of the files
    $lastmodified = 0;
    while( list(,$element) = each($elements) ) {
        $path = realpath($base . '/' . $element) ;

        if( ($type != 'js' && $type != 'css') || 
            ($type == 'js' && substr($path, -3) != '.js') || 
            ($type == 'css' && substr($path, -4) != '.css') ) {
            header ("HTTP/1.0 403 Forbidden") ;
            exit ;
        }

        if (substr($path, 0, strlen($base)) != $base || !file_exists($path)) {
            header ("HTTP/1.0 404 Not Found");
            exit;
        }

        $lastmodified = max($lastmodified, filemtime($path));
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,11 @@
 
     $type     = $_GET['type'];
     $elements = explode(',', $_GET['files']);
+
+    if( !in_array($type, array('css', 'js')) ) {
+        header ("HTTP/1.0 403 Forbidden") ;
+        exit ;
+    }
 
     // Determine last modification date of the files
     $lastmodified = 0;
```
