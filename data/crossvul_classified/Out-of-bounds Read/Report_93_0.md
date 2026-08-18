# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 93_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `93_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 6063-6103 of the vulnerable file.

    return "Flipping image";
  case LIBRAW_PROGRESS_APPLY_PROFILE:
    return "ICC conversion";
  case LIBRAW_PROGRESS_CONVERT_RGB:
    return "Converting to RGB";
  case LIBRAW_PROGRESS_STRETCH:
    return "Stretching image";
  case LIBRAW_PROGRESS_THUMB_LOAD:
    return "Loading thumbnail";
  default:
    return "Some strange things";
  }
}

#undef ID

#include "../internal/libraw_x3f.cpp"

void x3f_clear(void *p) { x3f_delete((x3f_t *)p); }

static char *utf2char(utf16_t *str, char *buffer)
{
  char *b = buffer;

  while (*str != 0x00)
  {
    char *chr = (char *)str;
    *b++ = *chr;
    str++;
  }
  *b = 0;
  return buffer;
}

static void *lr_memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
  register char *cur, *last;
  const char *cl = (const char *)l;
  const char *cs = (const char *)s;

  /* we need something to compare */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6080,18 +6080,19 @@
 
 void x3f_clear(void *p) { x3f_delete((x3f_t *)p); }
 
-static char *utf2char(utf16_t *str, char *buffer)
-{
+void utf2char(utf16_t *str, char *buffer, unsigned bufsz)
+{
+ if(bufsz<1) return;
+ buffer[bufsz-1] = 0;
   char *b = buffer;
 
-  while (*str != 0x00)
+  while (*str != 0x00 && --bufsz>0)
   {
     char *chr = (char *)str;
     *b++ = *chr;
     str++;
   }
   *b = 0;
-  return buffer;
 }
 
 static void *lr_memmem(const void *l, size_t l_len, const void *s, size_t s_len)
@@ -6155,8 +6156,8 @@
       for (i = 0; i < PL->num_properties; i++)
       {
         char name[100], value[100];
-        utf2char(P[i].name, name);
-        utf2char(P[i].value, value);
+        utf2char(P[i].name, name,sizeof(name));
+        utf2char(P[i].value, value,sizeof(value));
         if (!strcmp(name, "ISO"))
           imgdata.other.iso_speed = atoi(value);
         if (!strcmp(name, "CAMMANUF"))
```
