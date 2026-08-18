# CrossVul Fix Pair: Uncontrolled Resource Consumption in scala
**Pair ID:** 1931_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1931_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```scala
Lines 56-96 of the vulnerable file.

      case _ -> Root / status =>
        Response[IO](status = Status.fromInt(status.toInt).yolo)
          .putHeaders(Location(uri"/ok"))
          .pure[IO]
    }
    .orNotFound

  val defaultClient = Client.fromHttpApp(app)
  val client = FollowRedirect(3)(defaultClient)

  case class RedirectResponse(
      method: String,
      body: String
  )

  test("FollowRedirect should strip payload headers when switching to GET") {
    // We could test others, and other scenarios, but this was a pain.
    val req = Request[IO](PUT, uri"http://localhost/303").withEntity("foo")
    client
      .run(req)
      .use { case Ok(resp) =>
        resp.headers.get(CIString("X-Original-Content-Length")).map(_.value).pure[IO]
      }
      .map(_.get)
      .assertEquals("0")
  }

  test("FollowRedirect should Not redirect more than 'maxRedirects' iterations") {
    val statefulApp = HttpRoutes
      .of[IO] { case GET -> Root / "loop" =>
        val body = loopCounter.incrementAndGet.toString
        MovedPermanently(Location(uri"/loop")).map(_.withEntity(body))
      }
      .orNotFound
    val client = FollowRedirect(3)(Client.fromHttpApp(statefulApp))
    client
      .run(Request[IO](uri = uri"http://localhost/loop"))
      .use {
        case MovedPermanently(resp) => resp.as[String].map(_.toInt)
        case _ => IO.pure(-1)
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,7 +73,7 @@
     val req = Request[IO](PUT, uri"http://localhost/303").withEntity("foo")
     client
       .run(req)
-      .use { case Ok(resp) =>
+      .use { case resp =>
         resp.headers.get(CIString("X-Original-Content-Length")).map(_.value).pure[IO]
       }
       .map(_.get)
@@ -128,7 +128,7 @@
       Header("Authorization", "Bearer s3cr3t"))
     client
       .run(req)
-      .use { case Ok(resp) =>
+      .use { case resp =>
         resp.headers.get(CIString("X-Original-Authorization")).map(_.value).pure[IO]
       }
       .assertEquals(Some(""))
@@ -141,7 +141,7 @@
       Header("Authorization", "Bearer s3cr3t"))
     client
       .run(req)
-      .use { case Ok(resp) =>
+      .use { case resp =>
         resp.headers.get(CIString("X-Original-Authorization")).map(_.value).pure[IO]
       }
       .assertEquals(Some("Bearer s3cr3t"))
@@ -150,7 +150,7 @@
   test("FollowRedirect should Record the intermediate URIs") {
     client
       .run(Request[IO](uri = uri"http://localhost/loop/0"))
-      .use { case Ok(resp) =>
+      .use { resp =>
         IO.pure(FollowRedirect.getRedirectUris(resp))
       }
       .assertEquals(
@@ -164,7 +164,7 @@
   test("FollowRedirect should Not add any URIs when there are no redirects") {
     client
       .run(Request[IO](uri = uri"http://localhost/loop/100"))
-      .use { case Ok(resp) =>
+      .use { case resp =>
         IO.pure(FollowRedirect.getRedirectUris(resp))
       }
       .assertEquals(List.empty[Uri])
```
