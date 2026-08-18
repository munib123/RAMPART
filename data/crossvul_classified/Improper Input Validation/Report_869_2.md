# CrossVul Fix Pair: Improper Input Validation in csharp
**Pair ID:** 869_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `869_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```csharp
Lines 195-217 of the vulnerable file.

            foreach (var c in
                normalized.Where(c => CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark))
            {
                sb.Append(c);
            }

            return sb.ToString();
        }

        static string RemoveExtraHyphen(string text)
        {
            if (text.Contains("--"))
            {
                text = text.Replace("--", "-");
                return RemoveExtraHyphen(text);
            }

            return text;
        }

        #endregion
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -212,6 +212,22 @@
             return text;
         }
 
+        public static string SanitizePath(this string str)
+        {
+            if (str.Contains("..") || str.Contains("//"))
+                throw new ApplicationException("Invalid directory path");
+
+            return str;
+        }
+
+        public static string SanitizeFileName(this string str)
+        {
+            if (str.Contains("..") || str.Contains("//") || str.Count(x => x == '.') > 1)
+                throw new ApplicationException("Invalid file name");
+
+            return str;
+        }
+
         #endregion
     }
 }
```
