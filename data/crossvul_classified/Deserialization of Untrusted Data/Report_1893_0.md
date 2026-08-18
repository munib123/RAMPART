# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 1893_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1893_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 255-295 of the vulnerable file.

import io.onedev.server.util.work.BatchWorkManager;
import io.onedev.server.util.work.DefaultBatchWorkManager;
import io.onedev.server.util.work.DefaultWorkExecutor;
import io.onedev.server.util.work.WorkExecutor;
import io.onedev.server.util.xstream.CollectionConverter;
import io.onedev.server.util.xstream.HibernateProxyConverter;
import io.onedev.server.util.xstream.MapConverter;
import io.onedev.server.util.xstream.ReflectionConverter;
import io.onedev.server.util.xstream.StringConverter;
import io.onedev.server.util.xstream.VersionedDocumentConverter;
import io.onedev.server.web.DefaultUrlManager;
import io.onedev.server.web.DefaultWicketFilter;
import io.onedev.server.web.DefaultWicketServlet;
import io.onedev.server.web.ExpectedExceptionContribution;
import io.onedev.server.web.ResourcePackScopeContribution;
import io.onedev.server.web.WebApplication;
import io.onedev.server.web.WebApplicationConfigurator;
import io.onedev.server.web.avatar.AvatarManager;
import io.onedev.server.web.avatar.DefaultAvatarManager;
import io.onedev.server.web.component.diff.DiffRenderer;
import io.onedev.server.web.component.markdown.AttachmentUploadServlet;
import io.onedev.server.web.component.markdown.SourcePositionTrackExtension;
import io.onedev.server.web.component.markdown.emoji.EmojiExtension;
import io.onedev.server.web.component.taskbutton.TaskButton;
import io.onedev.server.web.editable.DefaultEditSupportRegistry;
import io.onedev.server.web.editable.EditSupport;
import io.onedev.server.web.editable.EditSupportLocator;
import io.onedev.server.web.editable.EditSupportRegistry;
import io.onedev.server.web.mapper.DynamicPathPageMapper;
import io.onedev.server.web.page.layout.DefaultUICustomization;
import io.onedev.server.web.page.layout.UICustomization;
import io.onedev.server.web.page.project.blob.render.BlobRendererContribution;
import io.onedev.server.web.page.test.TestPage;
import io.onedev.server.web.websocket.BuildEventBroadcaster;
import io.onedev.server.web.websocket.CodeCommentEventBroadcaster;
import io.onedev.server.web.websocket.CommitIndexedBroadcaster;
import io.onedev.server.web.websocket.DefaultWebSocketManager;
import io.onedev.server.web.websocket.IssueEventBroadcaster;
import io.onedev.server.web.websocket.PullRequestEventBroadcaster;
import io.onedev.server.web.websocket.WebSocketManager;
import io.onedev.server.web.websocket.WebSocketPolicyProvider;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -272,7 +272,6 @@
 import io.onedev.server.web.avatar.AvatarManager;
 import io.onedev.server.web.avatar.DefaultAvatarManager;
 import io.onedev.server.web.component.diff.DiffRenderer;
-import io.onedev.server.web.component.markdown.AttachmentUploadServlet;
 import io.onedev.server.web.component.markdown.SourcePositionTrackExtension;
 import io.onedev.server.web.component.markdown.emoji.EmojiExtension;
 import io.onedev.server.web.component.taskbutton.TaskButton;
@@ -557,8 +556,6 @@
 		bind(EditSupportRegistry.class).to(DefaultEditSupportRegistry.class);
 		bind(WebSocketManager.class).to(DefaultWebSocketManager.class);
 
-		bind(AttachmentUploadServlet.class);
-		
 		contributeFromPackage(EditSupport.class, EditSupport.class);
 		
 		bind(org.apache.wicket.protocol.http.WebApplication.class).to(WebApplication.class);
```
