# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 252_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `252_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 100-141 of the vulnerable file.


  /* clean up remainder */
  if ((len > 0) && (olen > 4))
  {
    unsigned char fragment;

    *out++ = B64Chars[in[0] >> 2];
    fragment = (in[0] << 4) & 0x30;
    if (len > 1)
      fragment |= in[1] >> 4;
    *out++ = B64Chars[fragment];
    *out++ = (len < 2) ? '=' : B64Chars[(in[1] << 2) & 0x3c];
    *out++ = '=';
  }
  *out = '\0';
  return (out - (char *) begin);
}

/**
 * mutt_b64_decode - Convert null-terminated base64 string to raw bytes
 * @param out Output buffer for the raw bytes
 * @param in  Input  buffer for the null-terminated base64-encoded string
 * @retval num Success, bytes written
 * @retval -1  Error
 *
 * This function performs base64 decoding. The resulting buffer is NOT
 * null-terminated. If the input buffer contains invalid base64 characters,
 * this function returns -1.
 */
int mutt_b64_decode(char *out, const char *in)
{
  int len = 0;
  unsigned char digit4;

  do
  {
    const unsigned char digit1 = in[0];
    if ((digit1 > 127) || (base64val(digit1) == BAD))
      return -1;
    const unsigned char digit2 = in[1];
    if ((digit2 > 127) || (base64val(digit2) == BAD))
      return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,8 +117,9 @@
 
 /**
  * mutt_b64_decode - Convert null-terminated base64 string to raw bytes
- * @param out Output buffer for the raw bytes
- * @param in  Input  buffer for the null-terminated base64-encoded string
+ * @param out  Output buffer for the raw bytes
+ * @param in   Input  buffer for the null-terminated base64-encoded string
+ * @param olen Length of the output buffer
  * @retval num Success, bytes written
  * @retval -1  Error
  *
@@ -126,7 +127,7 @@
  * null-terminated. If the input buffer contains invalid base64 characters,
  * this function returns -1.
  */
-int mutt_b64_decode(char *out, const char *in)
+int mutt_b64_decode(char *out, const char *in, size_t olen)
 {
   int len = 0;
   unsigned char digit4;
@@ -148,14 +149,20 @@
     in += 4;
 
     /* digits are already sanity-checked */
+    if (len == olen)
+      return len;
     *out++ = (base64val(digit1) << 2) | (base64val(digit2) >> 4);
     len++;
     if (digit3 != '=')
     {
+      if (len == olen)
+        return len;
       *out++ = ((base64val(digit2) << 4) & 0xf0) | (base64val(digit3) >> 2);
       len++;
       if (digit4 != '=')
       {
+        if (len == olen)
+          return len;
         *out++ = ((base64val(digit3) << 6) & 0xc0) | base64val(digit4);
         len++;
       }
```
