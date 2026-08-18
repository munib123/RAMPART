# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in scala
**Pair ID:** 2468_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2468_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```scala
Lines 1-27 of the vulnerable file.

package org.http4s
package server
package staticcontent

import cats.data._
import cats.effect._
import java.io.File
import org.http4s.headers.Range.SubRange
import org.http4s.headers._
import scala.concurrent.ExecutionContext

object FileService {
  type PathCollector[F[_]] = (File, Config[F], Request[F]) => OptionT[F, Response[F]]

  /** [[org.http4s.server.staticcontent.FileService]] configuration
    *
    * @param systemPath path prefix to the folder from which content will be served
    * @param pathPrefix prefix of Uri from which content will be served
    * @param pathCollector function that performs the work of collecting the file or rendering the directory into a response.
    * @param bufferSize buffer size to use for internal read buffers
    * @param executionContext `ExecutionContext` to use when collecting content
    * @param cacheStrategy strategy to use for caching purposes. Default to no caching.
    */
  final case class Config[F[_]](
      systemPath: String,
      pathCollector: PathCollector[F],
      pathPrefix: String,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,12 +4,22 @@
 
 import cats.data._
 import cats.effect._
+import cats.implicits._
 import java.io.File
+import java.nio.file.{LinkOption, Paths}
 import org.http4s.headers.Range.SubRange
 import org.http4s.headers._
+import org.http4s.server.middleware.TranslateUri
+import org.http4s.util.UrlCodingUtils.urlDecode
+import org.log4s.getLogger
 import scala.concurrent.ExecutionContext
+import scala.util.control.NoStackTrace
+import scala.util.{Failure, Success, Try}
+import java.nio.file.NoSuchFileException
 
 object FileService {
+  private[this] val logger = getLogger
+
   type PathCollector[F[_]] = (File, Config[F], Request[F]) => OptionT[F, Response[F]]
 
   /** [[org.http4s.server.staticcontent.FileService]] configuration
@@ -42,14 +52,46 @@
   }
 
   /** Make a new [[org.http4s.HttpService]] that serves static files. */
-  private[staticcontent] def apply[F[_]](config: Config[F])(implicit F: Effect[F]): HttpService[F] =
-    Kleisli {
-      case request if request.pathInfo.startsWith(config.pathPrefix) =>
-        getFile(s"${config.systemPath}/${getSubPath(request.pathInfo, config.pathPrefix)}")
-          .flatMap(f => config.pathCollector(f, config, request))
-          .semiflatMap(config.cacheStrategy.cache(request.pathInfo, _))
-      case _ => OptionT.none
+  private[staticcontent] def apply[F[_]](config: Config[F])(
+      implicit F: Effect[F]): HttpService[F] = {
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
+                        path.resolve(urlDecode(segment, plusIsSpace = true))
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
       implicit F: Sync[F]): OptionT[F, Response[F]] =
@@ -95,12 +137,4 @@
 
       case _ => OptionT.none
     }
-
-  // Attempts to sanitize the file location and retrieve the file. Returns None if the file doesn't exist.
-  private def getFile[F[_]](unsafePath: String)(implicit F: Sync[F]): OptionT[F, File] =
-    OptionT(F.delay {
-      val f = new File(PathNormalizer.removeDotSegments(unsafePath))
-      if (f.exists()) Some(f)
-      else None
-    })
 }
```
