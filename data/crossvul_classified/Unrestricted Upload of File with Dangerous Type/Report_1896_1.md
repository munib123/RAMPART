# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in java
**Pair ID:** 1896_1
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1896_1`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```java
Lines 36-76 of the vulnerable file.

import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.LoadableDetachableModel;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.protocol.http.WebSession;
import org.apache.wicket.request.cycle.RequestCycle;
import org.apache.wicket.util.lang.Bytes;
import org.eclipse.jgit.lib.FileMode;
import org.eclipse.jgit.lib.ObjectId;
import org.unbescape.javascript.JavaScriptEscape;

import com.google.common.base.Preconditions;

import io.onedev.commons.utils.PathUtils;
import io.onedev.commons.utils.StringUtils;
import io.onedev.server.git.BlobIdent;
import io.onedev.server.git.BlobIdentFilter;
import io.onedev.server.git.exception.GitException;
import io.onedev.server.model.Project;
import io.onedev.server.util.UrlUtils;
import io.onedev.server.web.ajaxlistener.ConfirmClickListener;
import io.onedev.server.web.behavior.ReferenceInputBehavior;
import io.onedev.server.web.component.blob.folderpicker.BlobFolderPicker;
import io.onedev.server.web.component.blob.picker.BlobPicker;
import io.onedev.server.web.component.dropzonefield.DropzoneField;
import io.onedev.server.web.component.floating.FloatingPanel;
import io.onedev.server.web.component.link.DropdownLink;
import io.onedev.server.web.component.tabbable.AjaxActionTab;
import io.onedev.server.web.component.tabbable.Tab;
import io.onedev.server.web.component.tabbable.Tabbable;
import io.onedev.server.web.page.project.blob.ProjectBlobPage;
import io.onedev.server.web.page.project.blob.render.BlobRenderContext;

@SuppressWarnings("serial")
abstract class InsertUrlPanel extends Panel {

	private static final MimetypesFileTypeMap MIME_TYPES = new MimetypesFileTypeMap();

	private static final MetaDataKey<String> ACTIVE_TAB = new MetaDataKey<String>(){};
	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,6 +53,7 @@
 import io.onedev.server.git.BlobIdentFilter;
 import io.onedev.server.git.exception.GitException;
 import io.onedev.server.model.Project;
+import io.onedev.server.util.FilenameUtils;
 import io.onedev.server.util.UrlUtils;
 import io.onedev.server.web.ajaxlistener.ConfirmClickListener;
 import io.onedev.server.web.behavior.ReferenceInputBehavior;
@@ -402,7 +403,8 @@
 					String attachmentName;
 					FileUpload upload = uploads.iterator().next();
 					try (InputStream is = upload.getInputStream()) {
-						attachmentName = attachmentSupport.saveAttachment(upload.getClientFileName(), is);
+						attachmentName = attachmentSupport.saveAttachment(
+								FilenameUtils.sanitizeFilename(upload.getClientFileName()), is);
 					} catch (IOException e) {
 						throw new RuntimeException(e);
 					}
```
