# CrossVul Fix Pair: Uncontrolled Resource Consumption in scala
**Pair ID:** 1931_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1931_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```scala
Lines 21-61 of the vulnerable file.

import cats.{Alternative, Applicative}
import cats.data.Kleisli
import cats.effect.{Async, Resource, Sync}
import cats.effect.std.Dispatcher
import cats.syntax.all._
import java.io.FileInputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.security.{KeyStore, Security}
import java.util.concurrent.ThreadFactory
import javax.net.ssl.{KeyManagerFactory, SSLContext, SSLEngine, SSLParameters, TrustManagerFactory}
import org.http4s.blaze.{BuildInfo => BlazeBuildInfo}
import org.http4s.blaze.channel.{
  ChannelOptions,
  DefaultPoolSize,
  ServerChannel,
  ServerChannelGroup,
  SocketConnection
}
import org.http4s.blaze.channel.nio1.NIO1SocketServerGroup
import org.http4s.blaze.channel.nio2.NIO2SocketServerGroup
import org.http4s.blaze.http.http2.server.ALPNServerSelector
import org.http4s.blaze.pipeline.LeafBuilder
import org.http4s.blaze.pipeline.stages.SSLStage
import org.http4s.blaze.util.TickWheelExecutor
import org.http4s.blazecore.{BlazeBackendBuilder, tickWheelResource}
import org.http4s.internal.threads.threadFactory
import org.http4s.server.ServerRequestKeys
import org.http4s.server.SSLKeyStoreSupport.StoreInfo
import org.http4s.server.blaze.BlazeServerBuilder._
import org.log4s.getLogger
import org.typelevel.vault._
import scala.collection.immutable
import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._
import scodec.bits.ByteVector

/** BlazeServerBuilder is the component for the builder pattern aggregating
  * different components to finally serve requests.
  *
  * Variables:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,7 +38,6 @@
   SocketConnection
 }
 import org.http4s.blaze.channel.nio1.NIO1SocketServerGroup
-import org.http4s.blaze.channel.nio2.NIO2SocketServerGroup
 import org.http4s.blaze.http.http2.server.ALPNServerSelector
 import org.http4s.blaze.pipeline.LeafBuilder
 import org.http4s.blaze.pipeline.stages.SSLStage
@@ -86,13 +85,13 @@
   *    this is necessary to recover totality from the error condition.
   * @param banner: Pretty log to display on server start. An empty sequence
   *    such as Nil disables this
+  * @param maxConnections: The maximum number of client connections that may be active at any time.
   */
-class BlazeServerBuilder[F[_]](
+class BlazeServerBuilder[F[_]] private (
     socketAddress: InetSocketAddress,
     executionContext: ExecutionContext,
     responseHeaderTimeout: Duration,
     idleTimeout: Duration,
-    isNio2: Boolean,
     connectorPoolSize: Int,
     bufferSize: Int,
     selectorThreadFactory: ThreadFactory,
@@ -105,6 +104,7 @@
     httpApp: HttpApp[F],
     serviceErrorHandler: ServiceErrorHandler[F],
     banner: immutable.Seq[String],
+    maxConnections: Int,
     val channelOptions: ChannelOptions
 )(implicit protected val F: Async[F])
     extends ServerBuilder[F]
@@ -118,7 +118,6 @@
       executionContext: ExecutionContext = executionContext,
       idleTimeout: Duration = idleTimeout,
       responseHeaderTimeout: Duration = responseHeaderTimeout,
-      isNio2: Boolean = isNio2,
       connectorPoolSize: Int = connectorPoolSize,
       bufferSize: Int = bufferSize,
       selectorThreadFactory: ThreadFactory = selectorThreadFactory,
@@ -131,6 +130,7 @@
       httpApp: HttpApp[F] = httpApp,
       serviceErrorHandler: ServiceErrorHandler[F] = serviceErrorHandler,
       banner: immutable.Seq[String] = banner,
+      maxConnections: Int = maxConnections,
       channelOptions: ChannelOptions = channelOptions
   ): Self =
     new BlazeServerBuilder(
@@ -138,7 +138,6 @@
       executionContext,
       responseHeaderTimeout,
       idleTimeout,
-      isNio2,
       connectorPoolSize,
       bufferSize,
       selectorThreadFactory,
@@ -151,6 +150,7 @@
       httpApp,
       serviceErrorHandler,
       banner,
+      maxConnections,
       channelOptions
     )
 
@@ -219,8 +219,6 @@
   def withSelectorThreadFactory(selectorThreadFactory: ThreadFactory): Self =
     copy(selectorThreadFactory = selectorThreadFactory)
 
-  def withNio2(isNio2: Boolean): Self = copy(isNio2 = isNio2)
-
   def withWebSockets(enableWebsockets: Boolean): Self =
     copy(enableWebSockets = enableWebsockets)
 
@@ -246,6 +244,9 @@
 
   def withChunkBufferMaxSize(chunkBufferMaxSize: Int): BlazeServerBuilder[F] =
     copy(chunkBufferMaxSize = chunkBufferMaxSize)
+
+  def withMaxConnections(maxConnections: Int): BlazeServerBuilder[F] =
+    copy(maxConnections = maxConnections)
 
   private def pipelineFactory(
       scheduler: TickWheelExecutor,
@@ -343,12 +344,8 @@
       else address
 
     val mkFactory: Resource[F, ServerChannelGroup] = Resource.make(F.delay {
-      if (isNio2)
-        NIO2SocketServerGroup
-          .fixedGroup(connectorPoolSize, bufferSize, channelOptions, selectorThreadFactory)
-      else
-        NIO1SocketServerGroup
-          .fixedGroup(connectorPoolSize, bufferSize, channelOptions, selectorThreadFactory)
+      NIO1SocketServerGroup
+        .fixed(connectorPoolSize, bufferSize, channelOptions, selectorThreadFactory, maxConnections)
     })(factory => F.delay(factory.closeGroup()))
 
     def mkServerChannel(
@@ -415,7 +412,6 @@
       executionContext = executionContext,
       responseHeaderTimeout = defaults.ResponseTimeout,
       idleTimeout = defaults.IdleTimeout,
-      isNio2 = false,
       connectorPoolSize = DefaultPoolSize,
       bufferSize = 64 * 1024,
       selectorThreadFactory = defaultThreadSelectorFactory,
@@ -428,6 +424,7 @@
       httpApp = defaultApp[F],
       serviceErrorHandler = DefaultServiceErrorHandler[F],
       banner = defaults.Banner,
+      maxConnections = defaults.MaxConnections,
       channelOptions = ChannelOptions(Vector.empty)
     )
 
```
