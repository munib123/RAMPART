# CrossVul Fix Pair: Incorrect Calculation in c
**Pair ID:** 3331_1
**Vulnerability Class:** Incorrect Calculation
**CWE:** CWE-682
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3331_1`)

## Vulnerability Information & PoC

## Description
Incorrect Calculation - When product performs a security-critical calculation incorrectly, it might lead to incorrect resource allocations, incorrect privilege assignments, or failed comparisons among other things.

## Vulnerable Code
```c
Lines 385-425 of the vulnerable file.

	b[2] = (n>>16)&0xff;
	b[3] = (n>>24)&0xff;
}

IW_IMPL(void) iw_set_ui16be(iw_byte *b, unsigned int n)
{
	b[0] = (n>>8)&0xff;
	b[1] = n&0xff;
}

IW_IMPL(void) iw_set_ui32be(iw_byte *b, unsigned int n)
{
	b[0] = (n>>24)&0xff;
	b[1] = (n>>16)&0xff;
	b[2] = (n>>8)&0xff;
	b[3] = n&0xff;
}

IW_IMPL(unsigned int) iw_get_ui16le(const iw_byte *b)
{
	return b[0] | (b[1]<<8);
}

IW_IMPL(unsigned int) iw_get_ui32le(const iw_byte *b)
{
	return b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24);
}

IW_IMPL(int) iw_get_i32le(const iw_byte *b)
{
	return (iw_int32)(iw_uint32)(b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24));
}

IW_IMPL(unsigned int) iw_get_ui16be(const iw_byte *b)
{
	return (b[0]<<8) | b[1];
}

IW_IMPL(unsigned int) iw_get_ui32be(const iw_byte *b)
{
	return (b[0]<<24) | (b[1]<<16) | (b[2]<<8) | b[3];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -402,27 +402,30 @@
 
 IW_IMPL(unsigned int) iw_get_ui16le(const iw_byte *b)
 {
-	return b[0] | (b[1]<<8);
+	return (unsigned int)b[0] | ((unsigned int)b[1]<<8);
 }
 
 IW_IMPL(unsigned int) iw_get_ui32le(const iw_byte *b)
 {
-	return b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24);
+	return (unsigned int)b[0] | ((unsigned int)b[1]<<8) |
+		((unsigned int)b[2]<<16) | ((unsigned int)b[3]<<24);
 }
 
 IW_IMPL(int) iw_get_i32le(const iw_byte *b)
 {
-	return (iw_int32)(iw_uint32)(b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24));
+	return (iw_int32)(iw_uint32)((unsigned int)b[0] | ((unsigned int)b[1]<<8) |
+		((unsigned int)b[2]<<16) | ((unsigned int)b[3]<<24));
 }
 
 IW_IMPL(unsigned int) iw_get_ui16be(const iw_byte *b)
 {
-	return (b[0]<<8) | b[1];
+	return ((unsigned int)b[0]<<8) | (unsigned int)b[1];
 }
 
 IW_IMPL(unsigned int) iw_get_ui32be(const iw_byte *b)
 {
-	return (b[0]<<24) | (b[1]<<16) | (b[2]<<8) | b[3];
+	return ((unsigned int)b[0]<<24) | ((unsigned int)b[1]<<16) |
+		((unsigned int)b[2]<<8) | (unsigned int)b[3];
 }
 
 // Accepts a flag indicating the endianness.
```
