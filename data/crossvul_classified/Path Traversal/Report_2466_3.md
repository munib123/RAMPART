# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in scala
**Pair ID:** 2466_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2466_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```scala
Lines 1-29 of the vulnerable file.

package org.http4s
package server
package staticcontent

import cats.data.{Kleisli, NonEmptyList, OptionT}
import cats.effect.{Blocker, ContextShift, Sync}
import cats.implicits._
import java.io.File
import org.http4s.headers.Range.SubRange
import org.http4s.headers._

object FileService {
  type PathCollector[F[_]] = (File, Config[F], Request[F]) => OptionT[F, Response[F]]

  /** [[org.http4s.server.staticcontent.FileService]] configuration
    *
    * @param systemPath path prefix to the folder from which content will be served
    * @param pathPrefix prefix of Uri from which content will be served
    * @param pathCollector function that performs the work of collecting the file or rendering the directory into a response.
    * @param bufferSize buffer size to use for internal read buffers
    * @param blockingExecutionContext `ExecutionContext` to use for blocking I/O
    * @param cacheStrategy strategy to use for caching purposes. Default to no caching.
    */
  final case class Config[F[_]](
      systemPath: String,
      blocker: Blocker,
      pathCollector: PathCollector[F],
      pathPrefix: String,
      bufferSize: Int,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,10 +6,18 @@
 import cats.effect.{Blocker, ContextShift, Sync}
 import cats.implicits._
 import java.io.File
+import java.nio.file.NoSuchFileException
+import java.nio.file.{LinkOption, Paths}
 import org.http4s.headers.Range.SubRange
 import org.http4s.headers._
+import org.http4s.server.middleware.TranslateUri
+import org.log4s.getLogger
+import scala.util.control.NoStackTrace
+import scala.util.{Failure, Success, Try}
 
 object FileService {
+  private[this] val logger = getLogger
+
   type PathCollector[F[_]] = (File, Config[F], Request[F]) => OptionT[F, Response[F]]
 
   /** [[org.http4s.server.staticcontent.FileService]] configuration
@@ -42,14 +50,45 @@
   }
 
   /** Make a new [[org.http4s.HttpRoutes]] that serves static files. */
-  private[staticcontent] def apply[F[_]](config: Config[F])(implicit F: Sync[F]): HttpRoutes[F] =
-    Kleisli {
-      case request if request.pathInfo.startsWith(config.pathPrefix) =>
-        OptionT(getFile(s"${config.systemPath}/${getSubPath(request.pathInfo, config.pathPrefix)}"))
-          .flatMap(f => config.pathCollector(f, config, request))
-          .semiflatMap(config.cacheStrategy.cache(request.pathInfo, _))
-      case _ => OptionT.none
+  private[staticcontent] def apply[F[_]](config: Config[F])(implicit F: Sync[F]): HttpRoutes[F] = {
+    object BadTraversal extends Exception with NoStackTrace
+    Try(Paths.get(config.systemPath).toRealPath()) match {
+      case Success(rootPath) =>
+        TranslateUri(config.pathPrefix)(Kleisli {
+          case request =>
+            request.pathInfo.split("/") match {
+              case Array(head, segments @ _*) if head.isEmpty =>
+                OptionT
+                  .liftF(F.catchNonFatal {
+                    segments.foldLeft(rootPath) {
+                      case (_, "" | "." | "..") => throw BadTraversal
+                      case (path, segment) =>
+                        path.resolve(Uri.decode(segment, plusIsSpace = true))
+                    }
+                  })
+                  .semiflatMap(path => F.delay(path.toRealPath(LinkOption.NOFOLLOW_LINKS)))
+                  .collect { case path if path.startsWith(rootPath) => path.toFile }
+                  .flatMap(f => config.pathCollector(f, config, request))
+                  .semiflatMap(config.cacheStrategy.cache(request.pathInfo, _))
+                  .recoverWith {
+                    case _: NoSuchFileException => OptionT.none
+                    case BadTraversal => OptionT.some(Response(Status.BadRequest))
+                  }
+              case _ => OptionT.none
+            }
+        })
+
+      case Failure(_: NoSuchFileException) =>
+        logger.error(
+          s"Could not find root path from FileService config: systemPath = ${config.systemPath}, pathPrefix = ${config.pathPrefix}. All requests will return none.")
+        Kleisli(_ => OptionT.none)
+
+      case Failure(e) =>
+        logger.error(e)(
+          s"Could not resolve root path from FileService config: systemPath = ${config.systemPath}, pathPrefix = ${config.pathPrefix}. All requests will fail with a 500.")
+        Kleisli(_ => OptionT.pure(Response(Status.InternalServerError)))
     }
+  }
 
   private def filesOnly[F[_]](file: File, config: Config[F], req: Request[F])(
       implicit F: Sync[F],
@@ -115,12 +154,4 @@
         }
       case _ => F.pure(None)
     }
-
-  // Attempts to sanitize the file location and retrieve the file. Returns None if the file doesn't exist.
-  private def getFile[F[_]](unsafePath: String)(implicit F: Sync[F]): F[Option[File]] =
-    F.delay {
-      val f = new File(Uri.removeDotSegments(unsafePath))
-      if (f.exists()) Some(f)
-      else None
-    }
 }
```
