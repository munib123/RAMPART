# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in scala
**Pair ID:** 2466_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2466_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```scala
Lines 1-23 of the vulnerable file.

package org.http4s.metrics

import org.http4s.{Method, Status}

/**
  * Describes an algebra capable of writing metrics to a metrics registry
  */
trait MetricsOps[F[_]] {

  /**
    * Increases the count of active requests
    *
    * @param classifier the classifier to apply
    */
  def increaseActiveRequests(classifier: Option[String]): F[Unit]

  /**
    * Decreases the count of active requests
    *
    * @param classifier the classifier to apply
    */
  def decreaseActiveRequests(classifier: Option[String]): F[Unit]

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,8 @@
 package org.http4s.metrics
 
-import org.http4s.{Method, Status}
+import cats.Foldable
+import cats.implicits._
+import org.http4s.{Method, Request, Status, Uri}
 
 /**
   * Describes an algebra capable of writing metrics to a metrics registry
@@ -57,6 +59,84 @@
       classifier: Option[String]): F[Unit]
 }
 
+object MetricsOps {
+
+  /**
+    * Given an exclude function, return a 'classifier' function, i.e. for application in
+    * org.http4s.server/client.middleware.Metrics#apply.
+    *
+    * Let's say you want a classifier that excludes integers since your paths consist of:
+    *   * GET    /users/{integer} = GET_users_*
+    *   * POST   /users           = POST_users
+    *   * PUT    /users/{integer} = PUT_users_*
+    *   * DELETE /users/{integer} = DELETE_users_*
+    *
+    * In such a case, we could use:
+    *
+    * classifierFMethodWithOptionallyExcludedPath(
+    *   exclude          = { str: String => scala.util.Try(str.toInt).isSuccess },
+    *   excludedValue    = "*",
+    *   intercalateValue = "_"
+    * )
+    *
+    *
+    * Chris Davenport notes the following on performance considerations of exclude's function value:
+    *
+    * > It's worth noting that this runs on every segment of a path. So note that if an intermediate Throwables with
+    * > Stack traces is known and discarded, there may be a performance penalty, such as the above example with Try(str.toInt).
+    * > I benchmarked some approaches and regex matches should generally be preferred over Throwable's
+    * > in this position.
+    *
+    * @param exclude For a given String, namely a path value, determine whether the value gets excluded.
+    * @param excludedValue Indicates the String value to be supplied for an excluded path's field.
+    * @param pathSeparator Value to use for separating the metrics fields' values
+    * @return Request[F] => Option[String]
+    */
+  def classifierFMethodWithOptionallyExcludedPath[F[_]](
+      exclude: String => Boolean,
+      excludedValue: String = "*",
+      pathSeparator: String = "_"
+  ): Request[F] => Option[String] = { request: Request[F] =>
+    val initial: String = request.method.name
+
+    val pathList: List[String] =
+      requestToPathList(request)
+
+    val minusExcluded: List[String] = pathList.map { value: String =>
+      if (exclude(value)) excludedValue else value
+    }
+
+    val result: String =
+      minusExcluded match {
+        case Nil => initial
+        case nonEmpty @ _ :: _ =>
+          initial + pathSeparator + Foldable[List]
+            .intercalate(nonEmpty, pathSeparator)
+      }
+
+    Some(result)
+  }
+
+  // The following was copied from
+  // https://github.com/http4s/http4s/blob/v0.20.17/dsl/src/main/scala/org/http4s/dsl/impl/Path.scala#L56-L64,
+  // and then modified.
+  private def requestToPathList[F[_]](request: Request[F]): List[String] = {
+    val str: String = request.pathInfo
+
+    if (str == "" || str == "/")
+      Nil
+    else {
+      val segments = str.split("/", -1)
+      // .head is safe because split always returns non-empty array
+      val segments0 = if (segments.head == "") segments.drop(1) else segments
+      val reversed: List[String] =
+        segments0.foldLeft[List[String]](Nil)((path, seg) => Uri.decode(seg) :: path)
+      reversed.reverse
+    }
+  }
+
+}
+
 /** Describes the type of abnormal termination*/
 sealed trait TerminationType
 
```
