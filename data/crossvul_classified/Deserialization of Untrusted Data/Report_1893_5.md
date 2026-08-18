# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 1893_5
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1893_5`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 9-49 of the vulnerable file.


import org.apache.shiro.web.env.EnvironmentLoader;
import org.apache.shiro.web.env.EnvironmentLoaderListener;
import org.apache.shiro.web.servlet.ShiroFilter;
import org.apache.wicket.protocol.http.WicketServlet;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.glassfish.jersey.servlet.ServletContainer;

import io.onedev.commons.launcher.bootstrap.Bootstrap;
import io.onedev.server.git.GitFilter;
import io.onedev.server.git.hookcallback.GitPostReceiveCallback;
import io.onedev.server.git.hookcallback.GitPreReceiveCallback;
import io.onedev.server.security.DefaultWebEnvironment;
import io.onedev.server.util.ServerConfig;
import io.onedev.server.util.jetty.ClasspathAssetServlet;
import io.onedev.server.util.jetty.FileAssetServlet;
import io.onedev.server.util.jetty.ServletConfigurator;
import io.onedev.server.web.asset.icon.IconScope;
import io.onedev.server.web.component.markdown.AttachmentUploadServlet;
import io.onedev.server.web.img.ImageScope;
import io.onedev.server.web.websocket.WebSocketManager;

public class ProductServletConfigurator implements ServletConfigurator {

	private final ServerConfig serverConfig;
	
	private final ShiroFilter shiroFilter;
	
    private final GitFilter gitFilter;
    
	private final GitPreReceiveCallback preReceiveServlet;
	
	private final GitPostReceiveCallback postReceiveServlet;
	
	private final WicketServlet wicketServlet;
	
	private final AttachmentUploadServlet attachmentUploadServlet;
	
	private final ServletContainer jerseyServlet;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,6 @@
 import io.onedev.server.util.jetty.FileAssetServlet;
 import io.onedev.server.util.jetty.ServletConfigurator;
 import io.onedev.server.web.asset.icon.IconScope;
-import io.onedev.server.web.component.markdown.AttachmentUploadServlet;
 import io.onedev.server.web.img.ImageScope;
 import io.onedev.server.web.websocket.WebSocketManager;
 
@@ -44,8 +43,6 @@
 	
 	private final WicketServlet wicketServlet;
 	
-	private final AttachmentUploadServlet attachmentUploadServlet;
-	
 	private final ServletContainer jerseyServlet;
 
 	private final WebSocketManager webSocketManager;
@@ -53,8 +50,7 @@
 	@Inject
 	public ProductServletConfigurator(ServerConfig serverConfig, ShiroFilter shiroFilter, GitFilter gitFilter, 
 			GitPreReceiveCallback preReceiveServlet, GitPostReceiveCallback postReceiveServlet, 
-			WicketServlet wicketServlet, WebSocketManager webSocketManager, 
-			AttachmentUploadServlet attachmentUploadServlet, ServletContainer jerseyServlet) {
+			WicketServlet wicketServlet, WebSocketManager webSocketManager, ServletContainer jerseyServlet) {
 		this.serverConfig = serverConfig;
 		this.shiroFilter = shiroFilter;
         this.gitFilter = gitFilter;
@@ -63,7 +59,6 @@
 		this.wicketServlet = wicketServlet;
 		this.webSocketManager = webSocketManager;
 		this.jerseyServlet = jerseyServlet;
-		this.attachmentUploadServlet = attachmentUploadServlet;
 	}
 	
 	@Override
@@ -87,8 +82,6 @@
 		 * match a path pattern
 		 */
 		context.addServlet(new ServletHolder(wicketServlet), "/");
-		
-		context.addServlet(new ServletHolder(attachmentUploadServlet), "/attachment_upload");
 		
 		context.addServlet(new ServletHolder(new ClasspathAssetServlet(ImageScope.class)), "/img/*");
 		context.addServlet(new ServletHolder(new ClasspathAssetServlet(IconScope.class)), "/icon/*");
```
