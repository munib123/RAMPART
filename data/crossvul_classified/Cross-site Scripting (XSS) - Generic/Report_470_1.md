# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 470_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `470_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 69-109 of the vulnerable file.

      for (var i = 0, m = names.length; i < m; i++) {
        if (copy[names[i]] === 1 && !defaults.hasOwnProperty(names[i])) continue;
        value = (this.attr||{})[names[i]]; if (value == null) {value = this[names[i]]}
        if (value != null) {attr.push(names[i]+'="'+this.toMathMLquote(value)+'"')}
      }
      this.toMathMLclass(attr);
      if (attr.length) {return " "+attr.join(" ")} else {return ""}
    },
    toMathMLclass: function (attr) {
      var CLASS = []; if (this["class"]) {CLASS.push(this["class"])}
      if (this.isa(MML.TeXAtom) && SETTINGS.texHints) {
        var TEXCLASS = ["ORD","OP","BIN","REL","OPEN","CLOSE","PUNCT","INNER","VCENTER"][this.texClass];
        if (TEXCLASS) {
          CLASS.push("MJX-TeXAtom-"+TEXCLASS)
          if (TEXCLASS === "OP" && !this.movablelimits) CLASS.push("MJX-fixedlimits");
        }
      }
      if (this.mathvariant && this.toMathMLvariants[this.mathvariant])
        {CLASS.push("MJX"+this.mathvariant)}
      if (this.variantForm) {CLASS.push("MJX-variant")}
      if (CLASS.length) {attr.unshift('class="'+CLASS.join(" ")+'"')}
    },
    toMathMLattribute: function (value) {
      if (typeof(value) === "string" &&
          value.replace(/ /g,"").match(/^(([-+])?(\d+(\.\d*)?|\.\d+))mu$/)) {
        // FIXME:  should take scriptlevel into account
        return (RegExp.$2||"")+((1/18)*RegExp.$3).toFixed(3).replace(/\.?0+$/,"")+"em";
      }
      else if (this.toMathMLvariants[value]) {return this.toMathMLvariants[value]}
      return this.toMathMLquote(value);
    },
    toMathMLvariants: {
      "-tex-caligraphic":      MML.VARIANT.SCRIPT,
      "-tex-caligraphic-bold": MML.VARIANT.BOLDSCRIPT,
      "-tex-oldstyle":         MML.VARIANT.NORMAL,
      "-tex-oldstyle-bold":    MML.VARIANT.BOLD,
      "-tex-mathit":           MML.VARIANT.ITALIC
    },
    
    toMathMLquote: function (string) {
      string = String(string).split("");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,7 +86,7 @@
       if (this.mathvariant && this.toMathMLvariants[this.mathvariant])
         {CLASS.push("MJX"+this.mathvariant)}
       if (this.variantForm) {CLASS.push("MJX-variant")}
-      if (CLASS.length) {attr.unshift('class="'+CLASS.join(" ")+'"')}
+      if (CLASS.length) {attr.unshift('class="'+this.toMathMLquote(CLASS.join(" "))+'"')}
     },
     toMathMLattribute: function (value) {
       if (typeof(value) === "string" &&
@@ -165,7 +165,7 @@
         var xmlEscapedTex = jax.originalText.replace(/[&<>]/g, function(item) {
             return { '>': '&gt;', '<': '&lt;','&': '&amp;' }[item]
         });
-        data.push(space+'    <annotation encoding="'+annotation+'">'+xmlEscapedTex+"</annotation>");
+        data.push(space+'    <annotation encoding="'+this.toMathMLquote(annotation)+'">'+xmlEscapedTex+"</annotation>");
         data.push(space+"  </semantics>");
       }
       return space+"<"+tag+attr+">\n"+data.join("\n")+"\n"+space+"</"+tag+">";
@@ -221,7 +221,7 @@
   });
   
   MML.entity.Augment({
-    toMathML: function (space) {return (space||"") + "&"+this.data[0]+";<!-- "+this.toString()+" -->"}
+    toMathML: function (space) {return (space||"") + "&"+this.toMathMLquote(this.data[0])+";<!-- "+this.toString()+" -->"}
   });
   
   MML.xml.Augment({
```
