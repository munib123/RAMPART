# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1040_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1040_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 376-416 of the vulnerable file.


Bool rfbOptOtpAuth(void)
{
  SecTypeData *s;

  for (s = secTypes; s->name != NULL; s++) {
    if (!strcmp(&s->name[strlen(s->name) - 3], "otp") && s->enabled)
      return TRUE;
  }

  return FALSE;
}


Bool rfbOptPamAuth(void)
{
  SecTypeData *s;

  for (s = secTypes; s->name != NULL; s++) {
    if ((!strcmp(s->name, "unixlogin") ||
         !strcmp(&s->name[strlen(s->name) - 5], "plain")) && s->enabled)
      return TRUE;
  }

  return FALSE;
}


Bool rfbOptRfbAuth(void)
{
  SecTypeData *s;

  for (s = secTypes; s->name != NULL; s++) {
    if (!strcmp(&s->name[strlen(s->name) - 3], "vnc") && s->enabled)
      return TRUE;
  }

  return FALSE;
}


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -393,7 +393,7 @@
 
   for (s = secTypes; s->name != NULL; s++) {
     if ((!strcmp(s->name, "unixlogin") ||
-         !strcmp(&s->name[strlen(s->name) - 5], "plain")) && s->enabled)
+         strstr(s->name, "plain")) && s->enabled)
       return TRUE;
   }
 
```
