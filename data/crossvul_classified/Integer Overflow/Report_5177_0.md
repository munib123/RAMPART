# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5177_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5177_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1346-1389 of the vulnerable file.

%
%    o profile: A StringInfo structure that contains the named profile.
%
*/

static void *DestroyProfile(void *profile)
{
  return((void *) DestroyStringInfo((StringInfo *) profile));
}

static inline const unsigned char *ReadResourceByte(const unsigned char *p,
  unsigned char *quantum)
{
  *quantum=(*p++);
  return(p);
}

static inline const unsigned char *ReadResourceLong(const unsigned char *p,
  unsigned int *quantum)
{
  *quantum=(size_t) (*p++ << 24);
  *quantum|=(size_t) (*p++ << 16);
  *quantum|=(size_t) (*p++ << 8);
  *quantum|=(size_t) (*p++ << 0);
  return(p);
}

static inline const unsigned char *ReadResourceShort(const unsigned char *p,
  unsigned short *quantum)
{
  *quantum=(unsigned short) (*p++ << 8);
  *quantum|=(unsigned short) (*p++ << 0);
  return(p);
}static inline void WriteResourceLong(unsigned char *p,
  const unsigned int quantum)
{
  unsigned char
    buffer[4];

  buffer[0]=(unsigned char) (quantum >> 24);
  buffer[1]=(unsigned char) (quantum >> 16);
  buffer[2]=(unsigned char) (quantum >> 8);
  buffer[3]=(unsigned char) quantum;
  (void) CopyMagickMemory(p,buffer,4);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1363,20 +1363,22 @@
 static inline const unsigned char *ReadResourceLong(const unsigned char *p,
   unsigned int *quantum)
 {
-  *quantum=(size_t) (*p++ << 24);
-  *quantum|=(size_t) (*p++ << 16);
-  *quantum|=(size_t) (*p++ << 8);
-  *quantum|=(size_t) (*p++ << 0);
+  *quantum=(unsigned int) (*p++) << 24;
+  *quantum|=(unsigned int) (*p++) << 16;
+  *quantum|=(unsigned int) (*p++) << 8;
+  *quantum|=(unsigned int) (*p++) << 0;
   return(p);
 }
 
 static inline const unsigned char *ReadResourceShort(const unsigned char *p,
   unsigned short *quantum)
 {
-  *quantum=(unsigned short) (*p++ << 8);
-  *quantum|=(unsigned short) (*p++ << 0);
+  *quantum=(unsigned short) (*p++) << 8;
+  *quantum|=(unsigned short) (*p++);
   return(p);
-}static inline void WriteResourceLong(unsigned char *p,
+}
+
+static inline void WriteResourceLong(unsigned char *p,
   const unsigned int quantum)
 {
   unsigned char
@@ -1744,13 +1746,14 @@
 
   if (endian == LSBEndian)
     {
-      value=(unsigned short) ((buffer[1] << 8) | buffer[0]);
-      quantum.unsigned_value=(value & 0xffff);
+      value=(unsigned short) buffer[1] << 8;
+      value|=(unsigned short) buffer[0];
+      quantum.unsigned_value=value & 0xffff;
       return(quantum.signed_value);
     }
-  value=(unsigned short) ((((unsigned char *) buffer)[0] << 8) |
-    ((unsigned char *) buffer)[1]);
-  quantum.unsigned_value=(value & 0xffff);
+  value=(unsigned short) buffer[0] << 8;
+  value|=(unsigned short) buffer[1];
+  quantum.unsigned_value=value & 0xffff;
   return(quantum.signed_value);
 }
 
@@ -1771,14 +1774,18 @@
 
   if (endian == LSBEndian)
     {
-      value=(unsigned int) ((buffer[3] << 24) | (buffer[2] << 16) |
-        (buffer[1] << 8 ) | (buffer[0]));
-      quantum.unsigned_value=(value & 0xffffffff);
+      value=(unsigned int) buffer[3] << 24;
+      value|=(unsigned int) buffer[2] << 16;
+      value|=(unsigned int) buffer[1] << 8;
+      value|=(unsigned int) buffer[0];
+      quantum.unsigned_value=value & 0xffffffff;
       return(quantum.signed_value);
     }
-  value=(unsigned int) ((buffer[0] << 24) | (buffer[1] << 16) |
-    (buffer[2] << 8) | buffer[3]);
-  quantum.unsigned_value=(value & 0xffffffff);
+  value=(unsigned int) buffer[0] << 24;
+  value|=(unsigned int) buffer[1] << 16;
+  value|=(unsigned int) buffer[2] << 8;
+  value|=(unsigned int) buffer[3];
+  quantum.unsigned_value=value & 0xffffffff;
   return(quantum.signed_value);
 }
 
@@ -2030,11 +2037,15 @@
         tag_value;
 
       q=(unsigned char *) (directory+2+(12*entry));
+      if (q > (exif+length-12))
+        break;  /* corrupt EXIF */
       tag_value=(ssize_t) ReadProfileShort(endian,q);
       format=(ssize_t) ReadProfileShort(endian,q+2);
       if ((format-1) >= EXIF_NUM_FORMATS)
         break;
       components=(ssize_t) ReadProfileLong(endian,q+4);
+      if (components < 0)
+        break;  /* corrupt EXIF */
       number_bytes=(size_t) components*format_bytes[format];
       if ((ssize_t) number_bytes < components)
         break;  /* prevent overflow */
```
