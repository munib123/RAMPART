# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 5841_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5841_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 14-54 of the vulnerable file.

// This community edition is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
// Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, see http://www.gnu.org/licenses/.
//
/////////////////////////////////////////////////////////////////////////////

package org.projectforge.web.core;

import java.util.Collection;

import org.apache.commons.lang.ObjectUtils;

public class JsonBuilder
{
  final private StringBuilder sb = new StringBuilder();

  /**
   * Creates Json result string from the given list.<br/>
   * [["Horst"], ["Klaus"], ...]] // For single property<br/>
   * [["Klein", "Horst"],["Schmidt", "Klaus"], ...] // For two Properties (e. g. name, first name) [["id:37", "Klein", "Horst"],["id:42",
   * "Schmidt", "Klaus"], ...] // For two Properties (e. g. name, first name) with id. <br/>
   * Uses ObjectUtils.toString(Object) for formatting each value.
   * @param col The array representation: List<Object> or List<Object[]>. If null then "[]" is returned.
   * @return
   */
  public static String buildToStringRows(final Collection< ? > col)
  {
    if (col == null) {
      return "[]";
    }
    final JsonBuilder builder = new JsonBuilder();
    return builder.append(col).getAsString();
  }

  public String getAsString()
  {
    return sb.toString();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,8 @@
 public class JsonBuilder
 {
   final private StringBuilder sb = new StringBuilder();
+
+  private boolean escapeHtml;
 
   /**
    * Creates Json result string from the given list.<br/>
@@ -47,6 +49,16 @@
     }
     final JsonBuilder builder = new JsonBuilder();
     return builder.append(col).getAsString();
+  }
+
+  /**
+   * @param escapeHtml the escapeHtml to set (default is false).
+   * @return this for chaining.
+   */
+  public JsonBuilder setEscapeHtml(final boolean escapeHtml)
+  {
+    this.escapeHtml = escapeHtml;
+    return this;
   }
 
   public String getAsString()
@@ -117,7 +129,32 @@
             t = "000" + Integer.toHexString(c);
             sb.append("\\u" + t.substring(t.length() - 4));
           } else {
-            sb.append(c);
+            if (escapeHtml == true) {
+              switch (c) {
+                case '<':
+                  sb.append("&lt;");
+                  break;
+                case '>':
+                  sb.append("&gt;");
+                  break;
+                case '&':
+                  sb.append("&amp;");
+                  break;
+                case '"':
+                  sb.append("&quot;");
+                  break;
+                case '\'':
+                  sb.append("&#x27;");
+                  break;
+                case '/':
+                  sb.append("&#x2F;");
+                  break;
+                default:
+                  sb.append(c);
+              }
+            } else {
+              sb.append(c);
+            }
           }
       }
     }
```
