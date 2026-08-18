# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in scala
**Pair ID:** 4479_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4479_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```scala
Lines 181-221 of the vulnerable file.

/**
 * A handler which accepts queries via http strings and returns
 * json encoded histogram details
 */
private[server] class HistogramQueryHandler(details: WithHistogramDetails)
    extends Service[Request, Response] {
  import HistogramQueryHandler._

  // If possible, access histograms inside statsReceiversLoaded
  private[this] def histograms: Map[String, HistogramDetail] = details.histogramDetails

  private[this] def jsonResponse(
    query: String,
    transform: Seq[BucketAndCount] => String
  ): Future[Response] =
    newResponse(
      contentType = ContentTypeJson,
      content = {
        val text = histograms.get(query) match {
          case Some(h) => transform(h.counts)
          case None => s"Key: $query is not a valid histogram."
        }
        Buf.Utf8(text)
      }
    )

  private[this] def renderHistogramsJson: String =
    JsonConverter.writeToString(histograms.map {
      case (key, value) =>
        (key, value.counts)
    })

  // needs a special case for the upper bound sentinel.
  private[this] def midPoint(bc: BucketAndCount): Double =
    if (bc.upperLimit >= Int.MaxValue) bc.lowerLimit
    else (bc.upperLimit + bc.lowerLimit) / 2.0

  private[this] def generateSummary(histoName: String): Option[Summary] = {
    histograms.get(histoName).map { detail =>
      val bcs = detail.counts.sortBy(_.lowerLimit)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -198,7 +198,7 @@
       content = {
         val text = histograms.get(query) match {
           case Some(h) => transform(h.counts)
-          case None => s"Key: $query is not a valid histogram."
+          case None => s"Key: ${escapeHtml(query)} is not a valid histogram."
         }
         Buf.Utf8(text)
       }
@@ -280,7 +280,7 @@
         if (histograms.contains(query))
           render
         else
-          s"Key: $query is not a valid histogram."
+          s"Key: ${escapeHtml(query)} is not a valid histogram."
       }
     )
 
```
