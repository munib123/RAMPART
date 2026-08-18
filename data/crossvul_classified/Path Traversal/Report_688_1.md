# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 688_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `688_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 1-27 of the vulnerable file.

package spark.embeddedserver.jetty;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.junit.After;
import org.junit.Test;
import spark.embeddedserver.EmbeddedServer;
import spark.route.Routes;
import spark.staticfiles.StaticFilesConfiguration;

import static org.mockito.Mockito.*;

public class EmbeddedJettyFactoryTest {
    private EmbeddedServer embeddedServer;

    @Test
    public void create() throws Exception {
        final JettyServerFactory jettyServerFactory = mock(JettyServerFactory.class);
        final StaticFilesConfiguration staticFilesConfiguration = mock(StaticFilesConfiguration.class);
        final Routes routes = mock(Routes.class);

        when(jettyServerFactory.create(100,10,10000)).thenReturn(new Server());

        final EmbeddedJettyFactory embeddedJettyFactory = new EmbeddedJettyFactory(jettyServerFactory);
        embeddedServer = embeddedJettyFactory.create(routes, staticFilesConfiguration, false);

        embeddedServer.ignite("localhost", 8080, null, 100,10,10000);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,13 +4,19 @@
 import org.eclipse.jetty.util.thread.QueuedThreadPool;
 import org.junit.After;
 import org.junit.Test;
+
 import spark.embeddedserver.EmbeddedServer;
 import spark.route.Routes;
 import spark.staticfiles.StaticFilesConfiguration;
 
-import static org.mockito.Mockito.*;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
+import static org.mockito.Mockito.when;
 
 public class EmbeddedJettyFactoryTest {
+
     private EmbeddedServer embeddedServer;
 
     @Test
@@ -19,14 +25,14 @@
         final StaticFilesConfiguration staticFilesConfiguration = mock(StaticFilesConfiguration.class);
         final Routes routes = mock(Routes.class);
 
-        when(jettyServerFactory.create(100,10,10000)).thenReturn(new Server());
+        when(jettyServerFactory.create(100, 10, 10000)).thenReturn(new Server());
 
         final EmbeddedJettyFactory embeddedJettyFactory = new EmbeddedJettyFactory(jettyServerFactory);
         embeddedServer = embeddedJettyFactory.create(routes, staticFilesConfiguration, false);
 
-        embeddedServer.ignite("localhost", 8080, null, 100,10,10000);
+        embeddedServer.ignite("localhost", 6757, null, 100, 10, 10000);
 
-        verify(jettyServerFactory, times(1)).create(100,10,10000);
+        verify(jettyServerFactory, times(1)).create(100, 10, 10000);
         verifyNoMoreInteractions(jettyServerFactory);
     }
 
@@ -42,7 +48,7 @@
         final EmbeddedJettyFactory embeddedJettyFactory = new EmbeddedJettyFactory(jettyServerFactory).withThreadPool(threadPool);
         embeddedServer = embeddedJettyFactory.create(routes, staticFilesConfiguration, false);
 
-        embeddedServer.ignite("localhost", 8080, null, 0,0,0);
+        embeddedServer.ignite("localhost", 6758, null, 0, 0, 0);
 
         verify(jettyServerFactory, times(1)).create(threadPool);
         verifyNoMoreInteractions(jettyServerFactory);
@@ -54,19 +60,21 @@
         final StaticFilesConfiguration staticFilesConfiguration = mock(StaticFilesConfiguration.class);
         final Routes routes = mock(Routes.class);
 
-        when(jettyServerFactory.create(100,10,10000)).thenReturn(new Server());
+        when(jettyServerFactory.create(100, 10, 10000)).thenReturn(new Server());
 
         final EmbeddedJettyFactory embeddedJettyFactory = new EmbeddedJettyFactory(jettyServerFactory).withThreadPool(null);
         embeddedServer = embeddedJettyFactory.create(routes, staticFilesConfiguration, false);
 
-        embeddedServer.ignite("localhost", 8080, null, 100,10,10000);
+        embeddedServer.ignite("localhost", 6759, null, 100, 10, 10000);
 
-        verify(jettyServerFactory, times(1)).create(100,10,10000);
+        verify(jettyServerFactory, times(1)).create(100, 10, 10000);
         verifyNoMoreInteractions(jettyServerFactory);
     }
 
     @After
     public void tearDown() throws Exception {
-        if(embeddedServer != null) embeddedServer.extinguish();
+        if (embeddedServer != null) {
+            embeddedServer.extinguish();
+        }
     }
 }
```
