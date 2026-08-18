# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in scala
**Pair ID:** 2467_5
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2467_5`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```scala
Lines 1-27 of the vulnerable file.

package org.http4s
package server
package staticcontent

import cats.data.{Kleisli, OptionT}
import cats.effect.{ContextShift, Effect}
import scala.concurrent.ExecutionContext

/**
  * Constructs new services to serve assets from Webjars
  */
object WebjarService {

  /** [[org.http4s.server.staticcontent.WebjarService]] configuration
    *
    * @param blockingExecutionContext execution context for blocking I/O
    * @param filter To filter which assets from the webjars should be served
    * @param cacheStrategy strategy to use for caching purposes. Default to no caching.
    */
  final case class Config[F[_]](
      blockingExecutionContext: ExecutionContext,
      filter: WebjarAssetFilter = _ => true,
      cacheStrategy: CacheStrategy[F] = NoopCacheStrategy[F])

  /**
    * Contains the information about an asset inside a webjar
    *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,10 @@
 
 import cats.data.{Kleisli, OptionT}
 import cats.effect.{ContextShift, Effect}
+import cats.implicits._
+import java.nio.file.{Path, Paths}
 import scala.concurrent.ExecutionContext
+import scala.util.control.NoStackTrace
 
 /**
   * Constructs new services to serve assets from Webjars
@@ -54,16 +57,32 @@
     * @param config The configuration for this service
     * @return The HttpRoutes
     */
-  def apply[F[_]: Effect: ContextShift](config: Config[F]): HttpRoutes[F] = Kleisli {
-    // Intercepts the routes that match webjar asset names
-    case request if request.method == Method.GET =>
-      OptionT
-        .pure[F](request.pathInfo)
-        .map(Uri.removeDotSegments)
-        .subflatMap(toWebjarAsset)
-        .filter(config.filter)
-        .flatMap(serveWebjarAsset(config, request)(_))
-    case _ => OptionT.none
+  def apply[F[_]](config: Config[F])(implicit F: Effect[F], cs: ContextShift[F]): HttpRoutes[F] = {
+    object BadTraversal extends Exception with NoStackTrace
+    val Root = Paths.get("")
+    Kleisli {
+      // Intercepts the routes that match webjar asset names
+      case request if request.method == Method.GET =>
+        request.pathInfo.split("/") match {
+          case Array(head, segments @ _*) if head.isEmpty =>
+            OptionT
+              .liftF(F.catchNonFatal {
+                segments.foldLeft(Root) {
+                  case (_, "" | "." | "..") => throw BadTraversal
+                  case (path, segment) =>
+                    path.resolve(Uri.decode(segment, plusIsSpace = true))
+                }
+              })
+              .subflatMap(toWebjarAsset)
+              .filter(config.filter)
+              .flatMap(serveWebjarAsset(config, request)(_))
+              .recover {
+                case BadTraversal => Response(Status.BadRequest)
+              }
+          case _ => OptionT.none
+        }
+      case _ => OptionT.none
+    }
   }
 
   /**
@@ -72,14 +91,17 @@
     * @param subPath The request path without the prefix
     * @return The WebjarAsset, or None if it couldn't be mapped
     */
-  private def toWebjarAsset(subPath: String): Option[WebjarAsset] =
-    Option(subPath)
-      .map(_.split("/", 4))
-      .collect {
-        case Array("", library, version, asset)
-            if library.nonEmpty && version.nonEmpty && asset.nonEmpty =>
-          WebjarAsset(library, version, asset)
-      }
+  private def toWebjarAsset(p: Path): Option[WebjarAsset] = {
+    val count = p.getNameCount
+    if (count > 2) {
+      val library = p.getName(0).toString
+      val version = p.getName(1).toString
+      val asset = p.subpath(2, count)
+      Some(WebjarAsset(library, version, asset.toString))
+    } else {
+      None
+    }
+  }
 
   /**
     * Returns an asset that matched the request if it's found in the webjar path
```
