# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 4533_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4533_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 5-45 of the vulnerable file.

 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */


package org.opencastproject.mediapackage.identifier;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;

/**
 * Simple and straightforward implementation of the {@link Id} interface.
 */
@XmlType
@XmlAccessorType(XmlAccessType.NONE)
public class IdImpl implements Id {

  /** The identifier */
  @XmlValue
  protected String id = null;

  /**
   * Needed for JAXB serialization
   */
  public IdImpl() {
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,8 @@
 
 package org.opencastproject.mediapackage.identifier;
 
+import java.util.regex.Pattern;
+
 import javax.xml.bind.annotation.XmlAccessType;
 import javax.xml.bind.annotation.XmlAccessorType;
 import javax.xml.bind.annotation.XmlType;
@@ -33,6 +35,8 @@
 @XmlType
 @XmlAccessorType(XmlAccessType.NONE)
 public class IdImpl implements Id {
+
+  private static final Pattern pattern = Pattern.compile("[\\w-_.:;()]+");
 
   /** The identifier */
   @XmlValue
@@ -50,7 +54,10 @@
    * @param id
    *          the identifier
    */
-  public IdImpl(String id) {
+  public IdImpl(final String id) {
+    if (!pattern.matcher(id).matches()) {
+      throw new IllegalArgumentException("Id must match " + pattern);
+    }
     this.id = id;
   }
 
@@ -60,7 +67,7 @@
    * @see org.opencastproject.mediapackage.identifier.Id#compact()
    */
   public String compact() {
-    return id.replaceAll("/", "-").replaceAll("\\\\", "-");
+    return toString();
   }
 
   @Override
```
