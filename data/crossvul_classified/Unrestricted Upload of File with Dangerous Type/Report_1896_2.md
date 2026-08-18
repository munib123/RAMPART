# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in java
**Pair ID:** 1896_2
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1896_2`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```java
Lines 43-83 of the vulnerable file.

import org.apache.wicket.request.cycle.RequestCycle;
import org.apache.wicket.request.http.WebRequest;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.wicket.request.resource.PackageResourceReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unbescape.javascript.JavaScriptEscape;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;

import io.onedev.commons.launcher.loader.AppLoader;
import io.onedev.server.OneDev;
import io.onedev.server.entitymanager.ProjectManager;
import io.onedev.server.model.Build;
import io.onedev.server.model.Issue;
import io.onedev.server.model.Project;
import io.onedev.server.model.PullRequest;
import io.onedev.server.model.User;
import io.onedev.server.util.markdown.MarkdownManager;
import io.onedev.server.util.validation.ProjectNameValidator;
import io.onedev.server.web.avatar.AvatarManager;
import io.onedev.server.web.behavior.AbstractPostAjaxBehavior;
import io.onedev.server.web.component.floating.FloatingPanel;
import io.onedev.server.web.component.link.DropdownLink;
import io.onedev.server.web.component.markdown.emoji.EmojiOnes;
import io.onedev.server.web.component.modal.ModalPanel;
import io.onedev.server.web.page.project.ProjectPage;
import io.onedev.server.web.page.project.blob.render.BlobRenderContext;

@SuppressWarnings("serial")
public class MarkdownEditor extends FormComponentPanel<String> {

	protected static final int ATWHO_LIMIT = 10;
	
	private static final Logger logger = LoggerFactory.getLogger(MarkdownEditor.class);
	
	private final boolean compactMode;
	
	private final boolean initialSplit;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,6 +60,7 @@
 import io.onedev.server.model.Project;
 import io.onedev.server.model.PullRequest;
 import io.onedev.server.model.User;
+import io.onedev.server.util.FilenameUtils;
 import io.onedev.server.util.markdown.MarkdownManager;
 import io.onedev.server.util.validation.ProjectNameValidator;
 import io.onedev.server.web.avatar.AvatarManager;
@@ -477,7 +478,8 @@
 				HttpServletRequest request = (HttpServletRequest) RequestCycle.get().getRequest().getContainerRequest();
 				HttpServletResponse response = (HttpServletResponse) RequestCycle.get().getResponse().getContainerResponse();
 				try {
-					String fileName = URLDecoder.decode(request.getHeader("File-Name"), StandardCharsets.UTF_8.name());
+					String fileName = FilenameUtils.sanitizeFilename(
+							URLDecoder.decode(request.getHeader("File-Name"), StandardCharsets.UTF_8.name()));
 					String attachmentName = getAttachmentSupport().saveAttachment(fileName, request.getInputStream());
 					response.getWriter().print(URLEncoder.encode(attachmentName, StandardCharsets.UTF_8.name()));
 					response.setStatus(HttpServletResponse.SC_OK);
```
