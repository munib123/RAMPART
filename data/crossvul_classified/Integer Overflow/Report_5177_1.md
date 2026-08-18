# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5177_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5177_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 510-550 of the vulnerable file.

  size_t *length)
{
  union
  {
    unsigned int
      unsigned_value;

    signed int
      signed_value;
  } quantum;

  int
    c;

  register ssize_t
    i;

  unsigned char
    buffer[4];

  size_t
    value;

  if (*length < 4)
    return(-1);
  for (i=0; i < 4; i++)
  {
    c=(int) (*(*p)++);
    (*length)--;
    buffer[i]=(unsigned char) c;
  }
  value=(size_t) (buffer[0] << 24);
  value|=buffer[1] << 16;
  value|=buffer[2] << 8;
  value|=buffer[3];
  quantum.unsigned_value=(value & 0xffffffff);
  return(quantum.signed_value);
}

static inline signed short ReadPropertyMSBShort(const unsigned char **p,
  size_t *length)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -527,7 +527,7 @@
   unsigned char
     buffer[4];
 
-  size_t
+  unsigned int
     value;
 
   if (*length < 4)
@@ -538,11 +538,11 @@
     (*length)--;
     buffer[i]=(unsigned char) c;
   }
-  value=(size_t) (buffer[0] << 24);
-  value|=buffer[1] << 16;
-  value|=buffer[2] << 8;
-  value|=buffer[3];
-  quantum.unsigned_value=(value & 0xffffffff);
+  value=(unsigned int) buffer[0] << 24;
+  value|=(unsigned int) buffer[1] << 16;
+  value|=(unsigned int) buffer[2] << 8;
+  value|=(unsigned int) buffer[3];
+  quantum.unsigned_value=value & 0xffffffff;
   return(quantum.signed_value);
 }
 
@@ -578,9 +578,9 @@
     (*length)--;
     buffer[i]=(unsigned char) c;
   }
-  value=(unsigned short) (buffer[0] << 8);
-  value|=buffer[1];
-  quantum.unsigned_value=(value & 0xffff);
+  value=(unsigned short) buffer[0] << 8;
+  value|=(unsigned short) buffer[1];
+  quantum.unsigned_value=value & 0xffff;
   return(quantum.signed_value);
 }
 
@@ -749,14 +749,18 @@
 
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
 
@@ -768,13 +772,17 @@
 
   if (endian == LSBEndian)
     {
-      value=(unsigned int) ((buffer[3] << 24) | (buffer[2] << 16) |
-        (buffer[1] << 8 ) | (buffer[0]));
-      return((unsigned int) (value & 0xffffffff));
-    }
-  value=(unsigned int) ((buffer[0] << 24) | (buffer[1] << 16) |
-    (buffer[2] << 8) | buffer[3]);
-  return((unsigned int) (value & 0xffffffff));
+      value=(unsigned int) buffer[3] << 24;
+      value|=(unsigned int) buffer[2] << 16;
+      value|=(unsigned int) buffer[1] << 8;
+      value|=(unsigned int) buffer[0];
+      return(value & 0xffffffff);
+    }
+  value=(unsigned int) buffer[0] << 24;
+  value|=(unsigned int) buffer[1] << 16;
+  value|=(unsigned int) buffer[2] << 8;
+  value|=(unsigned int) buffer[3];
+  return(value & 0xffffffff);
 }   
 
 static inline signed short ReadPropertySignedShort(const EndianType endian,
@@ -794,13 +802,14 @@
 
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
 
@@ -812,12 +821,13 @@
 
   if (endian == LSBEndian)
     {
-      value=(unsigned short) ((buffer[1] << 8) | buffer[0]);
-      return((unsigned short) (value & 0xffff));
-    }
-  value=(unsigned short) ((((unsigned char *) buffer)[0] << 8) |
-    ((unsigned char *) buffer)[1]);
-  return((unsigned short) (value & 0xffff));
+      value=(unsigned short) buffer[1] << 8;
+      value|=(unsigned short) buffer[0];
+      return(value & 0xffff);
+    }
+  value=(unsigned short) buffer[0] << 8;
+  value|=(unsigned short) buffer[1];
+  return(value & 0xffff);
 }
 
 static MagickBooleanType GetEXIFProperty(const Image *image,
@@ -1401,6 +1411,8 @@
         components;
 
       q=(unsigned char *) (directory+(12*entry)+2);
+      if (q > (exif+length-12))
+        break;  /* corrupt EXIF */
       if (GetValueFromSplayTree(exif_resources,q) == q)
         break;
       (void) AddValueToSplayTree(exif_resources,q,q);
@@ -1409,6 +1421,8 @@
       if (format >= (sizeof(tag_bytes)/sizeof(*tag_bytes)))
         break;
       components=(ssize_t) ReadPropertySignedLong(endian,q+4);
+      if (components < 0)
+        break;  /* corrupt EXIF */
       number_bytes=(size_t) components*tag_bytes[format];
       if (number_bytes < components)
         break;  /* prevent overflow */
```
