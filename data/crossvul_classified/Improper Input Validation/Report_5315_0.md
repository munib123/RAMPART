# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5315_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5315_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1438-1478 of the vulnerable file.

    return;
  datum=GetStringInfoDatum(profile_8bim);
  length=GetStringInfoLength(profile_8bim);
  for (p=datum; p < (datum+length-16); )
  {
    q=p;
    if (LocaleNCompare((char *) p,"8BIM",4) != 0)
      break;
    p+=4;
    p=ReadResourceShort(p,&id);
    p=ReadResourceByte(p,&length_byte);
    p+=length_byte;
    if (((length_byte+1) & 0x01) != 0)
      p++;
    if (p > (datum+length-4))
      break;
    p=ReadResourceLong(p,&value);
    count=(ssize_t) value;
    if ((count & 0x01) != 0)
      count++;
    if ((p > (datum+length-count)) || (count > (ssize_t) length))
      break;
    if (id != profile_id)
      p+=count;
    else
      {
        size_t
          extent,
          offset;

        ssize_t
          extract_extent;

        StringInfo
          *extract_profile;

        extract_extent=0;
        extent=(datum+length)-(p+count);
        if (profile == (StringInfo *) NULL)
          {
            offset=(q-datum);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1455,7 +1455,8 @@
     count=(ssize_t) value;
     if ((count & 0x01) != 0)
       count++;
-    if ((p > (datum+length-count)) || (count > (ssize_t) length))
+    if ((count < 0) || (p > (datum+length-count)) ||
+        (count > (ssize_t) length))
       break;
     if (id != profile_id)
       p+=count;
```
