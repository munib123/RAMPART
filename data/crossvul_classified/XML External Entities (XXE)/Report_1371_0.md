# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in csharp
**Pair ID:** 1371_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1371_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```csharp
Lines 445-486 of the vulnerable file.

            }

            UpdateInfoEventArgs args;

            using (Stream appCastStream = webResponse.GetResponseStream())
            {
                if (appCastStream != null)
                {
                    if (ParseUpdateInfoEvent != null)
                    {
                        using (StreamReader streamReader = new StreamReader(appCastStream))
                        {
                            string data = streamReader.ReadToEnd();
                            ParseUpdateInfoEventArgs parseArgs = new ParseUpdateInfoEventArgs(data);
                            ParseUpdateInfoEvent(parseArgs);
                            args = parseArgs.UpdateInfo;
                        }
                    }
                    else
                    {
                        XmlDocument receivedAppCastDocument = new XmlDocument();

                        try
                        {
                            receivedAppCastDocument.Load(appCastStream);

                            XmlNodeList appCastItems = receivedAppCastDocument.SelectNodes("item");

                            args = new UpdateInfoEventArgs();

                            if (appCastItems != null)
                            {
                                foreach (XmlNode item in appCastItems)
                                {
                                    XmlNode appCastVersion = item.SelectSingleNode("version");

                                    try
                                    {
                                        CurrentVersion = new Version(appCastVersion?.InnerText);
                                    }
                                    catch (Exception)
                                    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -462,8 +462,7 @@
                     }
                     else
                     {
-                        XmlDocument receivedAppCastDocument = new XmlDocument();
-
+                        XmlDocument receivedAppCastDocument = new XmlDocument {XmlResolver = null};
                         try
                         {
                             receivedAppCastDocument.Load(appCastStream);
```
