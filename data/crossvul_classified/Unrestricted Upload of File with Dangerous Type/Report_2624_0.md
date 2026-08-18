# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in cpp
**Pair ID:** 2624_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2624_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```cpp
Lines 317-357 of the vulnerable file.

  // Table of contents (ID3v2 chapters 1.0)

  if(frameID == "CTOC")
    return new TableOfContentsFrame(tagHeader, data, header);

  // Apple proprietary PCST (Podcast)

  if(frameID == "PCST")
    return new PodcastFrame(data, header);

  return new UnknownFrame(data, header);
}

void FrameFactory::rebuildAggregateFrames(ID3v2::Tag *tag) const
{
  if(tag->header()->majorVersion() < 4 &&
     tag->frameList("TDRC").size() == 1 &&
     tag->frameList("TDAT").size() == 1)
  {
    TextIdentificationFrame *tdrc =
      static_cast<TextIdentificationFrame *>(tag->frameList("TDRC").front());
    UnknownFrame *tdat = static_cast<UnknownFrame *>(tag->frameList("TDAT").front());

    if(tdrc->fieldList().size() == 1 &&
       tdrc->fieldList().front().size() == 4 &&
       tdat->data().size() >= 5)
    {
      String date(tdat->data().mid(1), String::Type(tdat->data()[0]));
      if(date.length() == 4) {
        tdrc->setText(tdrc->toString() + '-' + date.substr(2, 2) + '-' + date.substr(0, 2));
        if(tag->frameList("TIME").size() == 1) {
          UnknownFrame *timeframe = static_cast<UnknownFrame *>(tag->frameList("TIME").front());
          if(timeframe->data().size() >= 5) {
            String time(timeframe->data().mid(1), String::Type(timeframe->data()[0]));
            if(time.length() == 4) {
              tdrc->setText(tdrc->toString() + 'T' + time.substr(0, 2) + ':' + time.substr(2, 2));
            }
          }
        }
      }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -334,10 +334,11 @@
      tag->frameList("TDAT").size() == 1)
   {
     TextIdentificationFrame *tdrc =
-      static_cast<TextIdentificationFrame *>(tag->frameList("TDRC").front());
+      dynamic_cast<TextIdentificationFrame *>(tag->frameList("TDRC").front());
     UnknownFrame *tdat = static_cast<UnknownFrame *>(tag->frameList("TDAT").front());
 
-    if(tdrc->fieldList().size() == 1 &&
+    if(tdrc &&
+       tdrc->fieldList().size() == 1 &&
        tdrc->fieldList().front().size() == 4 &&
        tdat->data().size() >= 5)
     {
```
