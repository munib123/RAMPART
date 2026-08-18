# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in csharp
**Pair ID:** 4397_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4397_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```csharp
Lines 726-766 of the vulnerable file.


            RemoveComments(context as INode);

            DoPostProcess(dom, context as INode);
        }

        private void SanitizeStyleSheets(IHtmlDocument dom, string baseUrl)
        {
            foreach (var styleSheet in dom.StyleSheets.OfType<ICssStyleSheet>())
            {
                var styleTag = styleSheet.OwnerNode;

                for (int i = 0; i < styleSheet.Rules.Length;)
                {
                    var rule = styleSheet.Rules[i];
                    if (!SanitizeStyleRule(rule, styleTag, baseUrl) && RemoveAtRule(styleTag, rule))
                        styleSheet.RemoveAt(i);
                    else i++;
                }

                styleTag.InnerHtml = styleSheet.ToCss();
            }
        }

        private bool SanitizeStyleRule(ICssRule rule, IElement styleTag, string baseUrl)
        {
            if (!AllowedAtRules.Contains(rule.Type)) return false;

            if (rule is ICssStyleRule styleRule)
            {
                SanitizeStyleDeclaration(styleTag, styleRule.Style, baseUrl);
            }
            else
            {
                if (rule is ICssGroupingRule groupingRule)
                {
                    for (int i = 0; i < groupingRule.Rules.Length;)
                    {
                        var childRule = groupingRule.Rules[i];
                        if (!SanitizeStyleRule(childRule, styleTag, baseUrl) && RemoveAtRule(styleTag, childRule))
                            groupingRule.RemoveAt(i);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -743,7 +743,7 @@
                     else i++;
                 }
 
-                styleTag.InnerHtml = styleSheet.ToCss();
+                styleTag.InnerHtml = styleSheet.ToCss().Replace("<", "\\3c");
             }
         }
 
```
