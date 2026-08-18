# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 470_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `470_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 72-113 of the vulnerable file.

MathJax.Hub.Register.StartupHook("TeX Jax Ready",function () {
  var TEX = MathJax.InputJax.TeX;
  var MML = MathJax.ElementJax.mml;
  var UNICODE = MathJax.Extension["TeX/unicode"].unicode;
  
  //
  //  Add \unicode macro
  //
  TEX.Definitions.Add({macros: {unicode: 'Unicode'}},null,true);
  //
  //  Implementation of \unicode in parser
  //
  TEX.Parse.Augment({
    Unicode: function(name) {
      var HD = this.GetBrackets(name), font;
      if (HD) {
        if (HD.replace(/ /g,"").match(/^(\d+(\.\d*)?|\.\d+),(\d+(\.\d*)?|\.\d+)$/))
          {HD = HD.replace(/ /g,"").split(/,/); font = this.GetBrackets(name)}
            else {font = HD; HD = null}
      }
      var n = this.trimSpaces(this.GetArgument(name)),
          N = parseInt(n.match(/^x/) ? "0"+n : n);
      if (!UNICODE[N]) {UNICODE[N] = [800,200,font,N]}
      else if (!font) {font = UNICODE[N][2]}
      if (HD) {
        UNICODE[N][0] = Math.floor(HD[0]*1000);
        UNICODE[N][1] = Math.floor(HD[1]*1000);
      }
      var variant = this.stack.env.font, def = {};
      if (font) {
        UNICODE[N][2] = def.fontfamily = font.replace(/"/g,"'");
        if (variant) {
          if (variant.match(/bold/))   {def.fontweight = "bold"}
          if (variant.match(/italic|-mathit/)) {def.fontstyle = "italic"}
        }
      } else if (variant) {def.mathvariant = variant}
      def.unicode = [].concat(UNICODE[N]); // make a copy
      this.Push(MML.mtext(MML.entity("#"+n)).With(def));
    }
  });

  MathJax.Hub.Startup.signal.Post("TeX unicode Ready");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,8 +89,11 @@
           {HD = HD.replace(/ /g,"").split(/,/); font = this.GetBrackets(name)}
             else {font = HD; HD = null}
       }
-      var n = this.trimSpaces(this.GetArgument(name)),
-          N = parseInt(n.match(/^x/) ? "0"+n : n);
+      var n = this.trimSpaces(this.GetArgument(name)).replace(/^0x/,"x");
+      if (!n.match(/^(x[0-9A-Fa-f]+|[0-9]+)$/)) {
+        TEX.Error(["BadUnicode","Argument to \\unicode must be a number"]);
+      }
+      var N = parseInt(n.match(/^x/) ? "0"+n : n);
       if (!UNICODE[N]) {UNICODE[N] = [800,200,font,N]}
       else if (!font) {font = UNICODE[N][2]}
       if (HD) {
@@ -101,7 +104,7 @@
       if (font) {
         UNICODE[N][2] = def.fontfamily = font.replace(/"/g,"'");
         if (variant) {
-          if (variant.match(/bold/))   {def.fontweight = "bold"}
+          if (variant.match(/bold/)) {def.fontweight = "bold"}
           if (variant.match(/italic|-mathit/)) {def.fontstyle = "italic"}
         }
       } else if (variant) {def.mathvariant = variant}
```
