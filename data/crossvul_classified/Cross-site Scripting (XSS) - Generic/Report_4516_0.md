# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 4516_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4516_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 217-257 of the vulnerable file.

            }
            AtRuleMedia m = AtRuleMedia.getInstance(ac.getCssVersion());
            try {
                if (media != null) {
                    addMedias(m, media, ac);
                }
                cssFouffa.setAtRule(m);
            } catch (org.w3c.css.util.InvalidParamException e) {
                Errors er = new Errors();
                er.addError(new org.w3c.css.parser.CssError(url.toString(),
                        -1, e));
                notifyErrors(er);
                return;
            }
            ac.setReferrer(url);
            doneref = true;
            cssFouffa.parseStyle();
        } catch (Exception e) {
            Errors er = new Errors();
            er.addError(new org.w3c.css.parser.CssError(Messages.escapeString(url.toString()),
                    -1, e));
            notifyErrors(er);
        } finally {
            if (doneref) {
                ac.setReferrer(ref);
            }
        }
    }

    // add media, easy version for CSS version < 3, otherwise, reuse the parser
    private void addMedias(AtRuleMedia m, String medias, ApplContext ac) throws InvalidParamException {
        // before CSS3, let's parse it the easy way...
        if (ac.getCssVersion().compareTo(CssVersion.CSS3) < 0) {
            StringTokenizer tokens = new StringTokenizer(medias, ",");
            while (tokens.hasMoreTokens()) {
                m.addMedia(null, tokens.nextToken().trim(), ac);
            }
        } else {
            CssFouffa muP = new CssFouffa(ac, new StringReader(medias));
            try {
                AtRuleMedia arm = muP.parseMediaDeclaration();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -234,7 +234,7 @@
         } catch (Exception e) {
             Errors er = new Errors();
             er.addError(new org.w3c.css.parser.CssError(Messages.escapeString(url.toString()),
-                    -1, e));
+                    -1, new Exception(Messages.escapeString(e.getMessage()))));
             notifyErrors(er);
         } finally {
             if (doneref) {
```
