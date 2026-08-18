# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2379_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2379_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 81-121 of the vulnerable file.

      background: rgba(102, 102, 102, 1) ;
      margin:  20px auto;
      padding: 80px;
      text-align: center;
    }



</style>


<script>



$(window).load(function(){
  var uicss = mwd.querySelector('link[href*="/ui.css"]').sheet.cssRules, l = uicss.length, i = 0, html='';
  for( ;i<l;i++){
    var sel = uicss[i].selectorText;

    if(!!sel && sel.indexOf('.mw-icon-') === 0){
        var cls = sel.replace(".", '').split(':')[0];
        html +='<li><span class="'+cls+'"></span><em>.'+cls+'</em></li>';
    }
  }
  mw.$('#info-icon-list').html('<ul>'+html+'</ul>');

  mw.$("#ui-info-table h2").each(function(){
        var el = this;
        var li = mwd.createElement('li');
        li.innerHTML = "<a href='javascript:;'>"+this.innerHTML+"</a>";
        li.onclick = function(){
            mw.tools.scrollTo(el);
            mw.$("#ui-info-table tbody > tr:visible:first").hide();
            $(mw.tools.firstParentWithTag(el, 'tr')).show();
            mw.$(".mw-tooltip-mwexample").remove()
        }
        $("#apinav").append(li)
  });

});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,9 +98,14 @@
   for( ;i<l;i++){
     var sel = uicss[i].selectorText;
 
+
     if(!!sel && sel.indexOf('.mw-icon-') === 0){
+        var t = uicss[i].cssText.replace(/'/g, '"');
+        var glyph = t.split('"')[1].split('"')[0];
+
         var cls = sel.replace(".", '').split(':')[0];
-        html +='<li><span class="'+cls+'"></span><em>.'+cls+'</em></li>';
+        //html +='<li><span class="'+cls+'"></span><em>.'+cls+'</em></li>';
+        html +='<li><span style="font-family:Microweber">'+glyph+'</span><em>.'+cls+'</em></li>';
     }
   }
   mw.$('#info-icon-list').html('<ul>'+html+'</ul>');
```
