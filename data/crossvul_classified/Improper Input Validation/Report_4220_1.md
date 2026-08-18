# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4220_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4220_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 16-56 of the vulnerable file.


#ifndef NO_JPEG
struct jpegErrorManager
{
  struct jpeg_error_mgr pub;
  jmp_buf setjmp_buffer;
};

static void jpegErrorExit(j_common_ptr cinfo)
{
  jpegErrorManager *myerr = (jpegErrorManager *)cinfo->err;
  longjmp(myerr->setjmp_buffer, 1);
}
#endif

int LibRaw::unpack_thumb(void)
{
  CHECK_ORDER_LOW(LIBRAW_PROGRESS_IDENTIFY);
  CHECK_ORDER_BIT(LIBRAW_PROGRESS_THUMB_LOAD);

  try
  {
    if (!libraw_internal_data.internal_data.input)
      return LIBRAW_INPUT_CLOSED;

    int t_colors = libraw_internal_data.unpacker_data.thumb_misc >> 5 & 7;
    int t_bytesps = (libraw_internal_data.unpacker_data.thumb_misc & 31) / 8;

    if (!ID.toffset && !(imgdata.thumbnail.tlength > 0 &&
                         load_raw == &LibRaw::broadcom_load_raw) // RPi
    )
    {
      return LIBRAW_NO_THUMBNAIL;
    }
    else if (thumb_load_raw)
    {
      kodak_thumb_loader();
      T.tformat = LIBRAW_THUMBNAIL_BITMAP;
      SET_PROC_FLAG(LIBRAW_PROGRESS_THUMB_LOAD);
      return 0;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,25 @@
 {
   CHECK_ORDER_LOW(LIBRAW_PROGRESS_IDENTIFY);
   CHECK_ORDER_BIT(LIBRAW_PROGRESS_THUMB_LOAD);
+
+#define THUMB_SIZE_CHECKT(A) \
+  do { \
+    if (INT64(A) > 1024ULL * 1024ULL * LIBRAW_MAX_THUMBNAIL_MB) throw LIBRAW_EXCEPTION_IO_CORRUPT; \
+    if (INT64(A) > 0 &&  INT64(A) < 64ULL)        throw LIBRAW_EXCEPTION_IO_CORRUPT; \
+  } while (0)
+
+#define THUMB_SIZE_CHECKTNZ(A) \
+  do { \
+    if (INT64(A) > 1024ULL * 1024ULL * LIBRAW_MAX_THUMBNAIL_MB) throw LIBRAW_EXCEPTION_IO_CORRUPT; \
+    if (INT64(A) < 64ULL)        throw LIBRAW_EXCEPTION_IO_CORRUPT; \
+  } while (0)
+
+
+#define THUMB_SIZE_CHECKWH(W,H) \
+  do { \
+    if (INT64(W)*INT64(H) > 1024ULL * 1024ULL * LIBRAW_MAX_THUMBNAIL_MB) throw LIBRAW_EXCEPTION_IO_CORRUPT; \
+    if (INT64(W)*INT64(H) < 64ULL)        throw LIBRAW_EXCEPTION_IO_CORRUPT; \
+  } while (0)
 
   try
   {
@@ -65,6 +84,7 @@
 
         if (INT64(ID.toffset) + tsize > ID.input->size() + THUMB_READ_BEYOND)
           throw LIBRAW_EXCEPTION_IO_EOF;
+        THUMB_SIZE_CHECKT(tsize);
       }
 #else
 	if (0) {}
@@ -82,6 +102,8 @@
       ID.input->seek(ID.toffset, SEEK_SET);
       if (write_thumb == &LibRaw::jpeg_thumb)
       {
+        THUMB_SIZE_CHECKTNZ(T.tlength);
+
         if (T.thumb)
           free(T.thumb);
         T.thumb = (char *)malloc(T.tlength);
@@ -132,6 +154,8 @@
         if (colors != 1 && colors != 3)
           return LIBRAW_UNSUPPORTED_THUMBNAIL;
 
+        THUMB_SIZE_CHECKWH(T.twidth, T.theight);
+
         int tlength = T.twidth * T.theight;
         if (T.thumb)
           free(T.thumb);
@@ -172,6 +196,7 @@
       else if (write_thumb == &LibRaw::rollei_thumb)
       {
         int i;
+        THUMB_SIZE_CHECKWH(T.twidth, T.theight);
         int tlength = T.twidth * T.theight;
         if (T.thumb)
           free(T.thumb);
@@ -198,6 +223,7 @@
         if (t_bytesps > 1)
           throw LIBRAW_EXCEPTION_IO_CORRUPT; // 8-bit thumb, but parsed for more
                                              // bits
+        THUMB_SIZE_CHECKWH(T.twidth, T.theight);
         int t_length = T.twidth * T.theight * t_colors;
 
         if (T.tlength &&
@@ -219,6 +245,7 @@
                 T.tcolors = 1;
             }
             T.tlength = total_size;
+            THUMB_SIZE_CHECKTNZ(T.tlength);
             if (T.thumb)
               free(T.thumb);
             T.thumb = (char *)malloc(T.tlength);
@@ -254,6 +281,8 @@
         if (T.thumb)
           free(T.thumb);
 
+        THUMB_SIZE_CHECKTNZ(T.tlength);
+
         T.thumb = (char *)malloc(T.tlength);
         if (!T.tcolors)
           T.tcolors = t_colors;
@@ -278,6 +307,10 @@
         int i_length = T.twidth * T.theight * t_colors * 2;
         if (!T.tlength)
           T.tlength = o_length;
+        THUMB_SIZE_CHECKTNZ(o_length);
+        THUMB_SIZE_CHECKTNZ(i_length);
+        THUMB_SIZE_CHECKTNZ(T.tlength);
+
         ushort *t_thumb = (ushort *)calloc(i_length, 1);
         ID.input->read(t_thumb, 1, i_length);
         if ((libraw_internal_data.unpacker_data.order == 0x4949) ==
```
