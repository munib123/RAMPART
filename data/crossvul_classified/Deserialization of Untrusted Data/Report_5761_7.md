# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 5761_7
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5761_7`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 10-50 of the vulnerable file.

 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

package org.richfaces.renderkit.html;


import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.Serializable;

import javax.faces.FacesException;
import javax.faces.component.UIComponentBase;
import javax.faces.context.FacesContext;
import javax.faces.el.MethodBinding;

import org.ajax4jsf.resource.GifRenderer;
import org.ajax4jsf.resource.ImageRenderer;
import org.ajax4jsf.resource.InternetResourceBase;
import org.ajax4jsf.resource.JpegRenderer;
import org.ajax4jsf.resource.PngRenderer;
import org.ajax4jsf.resource.ResourceContext;
import org.ajax4jsf.resource.ResourceRenderer;
import org.ajax4jsf.util.HtmlColor;
import org.richfaces.component.UIPaint2D;

/**
 * Resource for create image by managed bean method
 * @author asmirnov@exadel.com (latest modification by $Author: aizobov $)
 * @version $Revision: 1.4 $ $Date: 2007/02/28 10:35:23 $
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,6 @@
 import java.awt.Graphics2D;
 import java.awt.image.BufferedImage;
 import java.io.IOException;
-import java.io.Serializable;
 
 import javax.faces.FacesException;
 import javax.faces.component.UIComponentBase;
@@ -41,6 +40,7 @@
 import org.ajax4jsf.resource.PngRenderer;
 import org.ajax4jsf.resource.ResourceContext;
 import org.ajax4jsf.resource.ResourceRenderer;
+import org.ajax4jsf.resource.SerializableResource;
 import org.ajax4jsf.util.HtmlColor;
 import org.richfaces.component.UIPaint2D;
 
@@ -126,7 +126,7 @@
 		}
 	}
 
-	private static final class ImageData implements Serializable {
+	private static final class ImageData implements SerializableResource {
 
 		private static final long serialVersionUID = 4452040100045367728L;
 		
```
