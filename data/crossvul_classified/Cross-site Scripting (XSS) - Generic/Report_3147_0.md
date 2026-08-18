# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 3147_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3147_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 186-226 of the vulnerable file.

     <table cellSpacing="0" cellPadding="0" align="center" border="0">
      <tr>
       <td>
       <span fckLang="PageDlgName">Page name</span><br>
       <select id="txtName" size="1">
       %s
       </select>
     </td>
    </tr>
   </table>
  </td>
 </tr>
</table>
</body>
</html>
''' % "".join(["<option>%s</option>\n" % wikiutil.escape(p) for p in pages]))

def link_dialog(request):
    # list of wiki pages
    name = request.values.get("pagename", "")
    if name:
        from MoinMoin import search
        # XXX error handling!
        searchresult = search.searchPages(request, 't:"%s"' % name)

        pages = [p.page_name for p in searchresult.hits]
        pages.sort()
        pages[0:0] = [name]
        page_list = '''
         <tr>
          <td colspan=2>
           <select id="sctPagename" size="1" onchange="OnChangePagename(this.value);">
           %s
           </select>
          <td>
         </tr>
''' % "\n".join(['<option value="%s">%s</option>' % (wikiutil.escape(page), wikiutil.escape(page))
                 for page in pages])
    else:
        page_list = ""

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -203,6 +203,7 @@
 def link_dialog(request):
     # list of wiki pages
     name = request.values.get("pagename", "")
+    name_escaped = wikiutil.escape(name)
     if name:
         from MoinMoin import search
         # XXX error handling!
@@ -299,7 +300,7 @@
         <tr>
          <td>
           <span fckLang="PageDlgName">Page Name</span><br>
-          <input id="txtPagename" name="pagename" size="30" value="%(name)s">
+          <input id="txtPagename" name="pagename" size="30" value="%(name_escaped)s">
          </td>
          <td valign="bottom">
            <input id=btnSearchpage type="submit" value="Search">
```
