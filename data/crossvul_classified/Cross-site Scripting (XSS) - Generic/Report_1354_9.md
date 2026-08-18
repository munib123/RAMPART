# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1354_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1354_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 189-229 of the vulnerable file.

  }, {
      "title": "Img element inside shadow DOM template",
      "payload": "<body><template><s><template><s><img src=x onerror=alert(1)>@shafigullin</s></template></s></template>",
      "expected": "<template><s><template><s><img src=\"x\">@shafigullin</s></template></s></template>"
  }, {
      "title": "Low-range-ASCII obfuscated JavaScript URI",
      "payload": "<a href=\"\u0001java\u0003script:alert(1)\">@shafigullin<a>",
      "expected": [
          "<a>@shafigullin</a><a></a>",
          "<a>@shafigullin<a></a>"
      ]
  }, {
      "title": "Img inside style inside broken option element",
      "payload": "\u0001<option><style></option></select><b><img src=x onerror=alert(1)></style></option>",
      "expected": "\u0001<option><style></option></select><b><img src=x onerror=alert(1)></style></option>"
  }, {
      "title": "Iframe inside option element",
      "payload": "<option><iframe></select><b><script>alert(1)</script>",
      "expected": [
          "<option><b></b></option>",
          "<option>&lt;/select&gt;&lt;b&gt;&lt;script&gt;alert(1)&lt;/script&gt;</option>"
      ]
  }, {
      "title": "Closing Iframe and option",
      "payload": "</iframe></option>",
      "expected": ""
  }, {
      "title": "Image after style to trick jQuery tag-completion",
      "payload": "<b><style><style/><img src=x onerror=alert(1)>",
      "expected": "<b><style><style/><img src=x onerror=alert(1)></style></b>"
  }, {
      "title": "Image after self-closing style to trick jQuery tag-completion",
      "payload": "<b><style><style////><img src=x onerror=alert(1)></style>",
      "expected": "<b><style><style////><img src=x onerror=alert(1)></style></b>"
  }, {
      "title": "MathML example",
      "payload": "<math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"block\">\n  <mrow>\n    <menclose notation=\"box\"><mi>a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\"><mi mathcolor=\"#FF0000\">a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\" mathcolor=\"#FF0000\"><mi>a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\" mathbackground=\"#80FF80\"><mi mathcolor=\"#FF0000\">a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\" mathcolor=\"#FF0000\" mathbackground=\"#80FF80\"><mi>a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\"><mi mathbackground=\"#80FF80\">a</mi></menclose>\n  </mrow>\n</math>",
      "expected": [
          "<math display=\"block\" xmlns=\"http://www.w3.org/1998/Math/MathML\">\n  <mrow>\n    <menclose notation=\"box\"><mi>a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\"><mi mathcolor=\"#FF0000\">a</mi></menclose><mo>,</mo>\n    <menclose mathcolor=\"#FF0000\" notation=\"box\"><mi>a</mi></menclose><mo>,</mo>\n    <menclose mathbackground=\"#80FF80\" notation=\"box\"><mi mathcolor=\"#FF0000\">a</mi></menclose><mo>,</mo>\n    <menclose mathbackground=\"#80FF80\" mathcolor=\"#FF0000\" notation=\"box\"><mi>a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\"><mi mathbackground=\"#80FF80\">a</mi></menclose>\n  </mrow>\n</math>",
          "<math display=\"block\" xmlns=\"http://www.w3.org/1998/Math/MathML\">\n  <mrow>\n    <menclose notation=\"box\"><mi>a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\"><mi mathcolor=\"#FF0000\">a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\" mathcolor=\"#FF0000\"><mi>a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\" mathbackground=\"#80FF80\"><mi mathcolor=\"#FF0000\">a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\" mathbackground=\"#80FF80\" mathcolor=\"#FF0000\"><mi>a</mi></menclose><mo>,</mo>\n    <menclose notation=\"box\"><mi mathbackground=\"#80FF80\">a</mi></menclose>\n  </mrow>\n</math>",
... (excerpt truncated)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -206,7 +206,8 @@
       "payload": "<option><iframe></select><b><script>alert(1)</script>",
       "expected": [
           "<option><b></b></option>",
-          "<option>&lt;/select&gt;&lt;b&gt;&lt;script&gt;alert(1)&lt;/script&gt;</option>"
+          "<option>&lt;/select&gt;&lt;b&gt;&lt;script&gt;alert(1)&lt;/script&gt;</option>",
+          "<option></option>"
       ]
   }, {
       "title": "Closing Iframe and option",
@@ -834,7 +835,8 @@
       "payload": "<div id=\"121\"><html xmlns=\"http://www.w3.org/1999/xhtml\"\nxmlns:svg=\"http://www.w3.org/2000/svg\">\n<body style=\"background:gray\">\n<iframe src=\"http://example.com/\" style=\"width:800px; height:350px; border:none; mask: url(#maskForClickjacking);\"/>\n<svg:svg>\n<svg:mask id=\"maskForClickjacking\" maskUnits=\"objectBoundingBox\" maskContentUnits=\"objectBoundingBox\">\n    <svg:rect x=\"0.0\" y=\"0.0\" width=\"0.373\" height=\"0.3\" fill=\"white\"/>\n    <svg:circle cx=\"0.45\" cy=\"0.7\" r=\"0.075\" fill=\"white\"/>\n</svg:mask>\n</svg:svg>\n</body>\n</html>//[\"'`-->]]>]</div>",
       "expected": [
           "<div id=\"121\">\n\n\n\n\n    \n    \n\n\n\n//[\"'`--&gt;]]&gt;]</div>",
-          "<div id=\"121\">\n\n\n&lt;svg:svg&gt;\n&lt;svg:mask id=\"maskForClickjacking\" maskUnits=\"objectBoundingBox\" maskContentUnits=\"objectBoundingBox\"&gt;\n    &lt;svg:rect x=\"0.0\" y=\"0.0\" width=\"0.373\" height=\"0.3\" fill=\"white\"/&gt;\n    &lt;svg:circle cx=\"0.45\" cy=\"0.7\" r=\"0.075\" fill=\"white\"/&gt;\n&lt;/svg:mask&gt;\n&lt;/svg:svg&gt;\n&lt;/body&gt;\n&lt;/html&gt;//[\"'`--&gt;]]&gt;]&lt;/div&gt;</div>"
+          "<div id=\"121\">\n\n\n&lt;svg:svg&gt;\n&lt;svg:mask id=\"maskForClickjacking\" maskUnits=\"objectBoundingBox\" maskContentUnits=\"objectBoundingBox\"&gt;\n    &lt;svg:rect x=\"0.0\" y=\"0.0\" width=\"0.373\" height=\"0.3\" fill=\"white\"/&gt;\n    &lt;svg:circle cx=\"0.45\" cy=\"0.7\" r=\"0.075\" fill=\"white\"/&gt;\n&lt;/svg:mask&gt;\n&lt;/svg:svg&gt;\n&lt;/body&gt;\n&lt;/html&gt;//[\"'`--&gt;]]&gt;]&lt;/div&gt;</div>",
+          "<div id=\"121\">\n\n</div>"
       ]
   }, {
       "title": "iframe (sandboxed)",
@@ -926,7 +928,8 @@
       "expected": [
           "<div id=\"134\">\n&lt;%\n\n<img alt=\"%></xmp><img src=xx onerror=alert(134)//\">\n\n %&gt;/\nalert(2)\n\n\nXXX\n<style>\n*['<!--']{}\n</style>\n--&gt;{}\n*{color:red}//[\"'`--&gt;]]&gt;]</div>",
           "<div id=\"134\">\n&lt;%\n\n<img alt=\"%&gt;&lt;/xmp&gt;&lt;img src=xx onerror=alert(134)//\">\n\n %&gt;/\nalert(2)\n\n\nXXX\n<style>\n*['<!--']{}\n</style>\n--&gt;{}\n*{color:red}//[\"'`--&gt;]]&gt;]</div>",
-          "<div id=\"134\">\n&lt;%\n\n\n\n %&gt;/\nalert(2)\n\n\nXXX\n<style>\n*['<!--']{}\n</style>\n--&gt;{}\n*{color:red}//[\"'`--&gt;]]&gt;]</div>"
+          "<div id=\"134\">\n&lt;%\n\n\n\n %&gt;/\nalert(2)\n\n\nXXX\n<style>\n*['<!--']{}\n</style>\n--&gt;{}\n*{color:red}//[\"'`--&gt;]]&gt;]</div>",
+          "<div id=\"134\">\n<img alt=\"%></xmp><img src=xx onerror=alert(134)//\">\n\n %&gt;/\nalert(2)\n\n\nXXX\n<style>\n*['<!--']{}\n</style>\n--&gt;{}\n*{color:red}//[\"'`--&gt;]]&gt;]</div>"
       ]
   }, {
       "title": "SVG",
@@ -1053,5 +1056,17 @@
       "expected": [
           ""
       ]
+  }, {
+      "title": "Tests against removal-based mXSS behavior 1/2",
+      "payload": "<xmp><svg><b><style><b title='</style><img>'>",
+      "expected": [
+          ""
+      ]
+  }, {
+      "title": "Tests against removal-based mXSS behavior 2/2",
+      "payload": "<noembed><svg><b><style><b title='</style><img>'>",
+      "expected": [
+          ""
+      ]
   }
 ];
```
