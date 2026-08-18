# CrossVul Fix Pair: Incorrect Calculation in go
**Pair ID:** 2002_0
**Vulnerability Class:** Incorrect Calculation
**CWE:** CWE-682
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2002_0`)

## Vulnerability Information & PoC

## Description
Incorrect Calculation - When product performs a security-critical calculation incorrectly, it might lead to incorrect resource allocations, incorrect privilege assignments, or failed comparisons among other things.

## Vulnerable Code
```go
Lines 369-409 of the vulnerable file.

	p224Square(&f4, &f3, &c)   // 2**97 - 2
	for i := 0; i < 23; i++ {  // 2**120 - 2**24
		p224Square(&f4, &f4, &c)
	}
	p224Mul(&f2, &f4, &f2, &c) // 2**120 - 1
	for i := 0; i < 6; i++ {   // 2**126 - 2**6
		p224Square(&f2, &f2, &c)
	}
	p224Mul(&f1, &f1, &f2, &c) // 2**126 - 1
	p224Square(&f1, &f1, &c)   // 2**127 - 2
	p224Mul(&f1, &f1, in, &c)  // 2**127 - 1
	for i := 0; i < 97; i++ {  // 2**224 - 2**97
		p224Square(&f1, &f1, &c)
	}
	p224Mul(out, &f1, &f3, &c) // 2**224 - 2**96 - 1
}

// p224Contract converts a FieldElement to its unique, minimal form.
//
// On entry, in[i] < 2**29
// On exit, in[i] < 2**28
func p224Contract(out, in *p224FieldElement) {
	copy(out[:], in[:])

	for i := 0; i < 7; i++ {
		out[i+1] += out[i] >> 28
		out[i] &= bottom28Bits
	}
	top := out[7] >> 28
	out[7] &= bottom28Bits

	out[0] -= top
	out[3] += top << 12

	// We may just have made out[i] negative. So we carry down. If we made
	// out[0] negative then we know that out[3] is sufficiently positive
	// because we just added to it.
	for i := 0; i < 3; i++ {
		mask := uint32(int32(out[i]) >> 31)
		out[i] += (1 << 28) & mask
		out[i+1] -= 1 & mask
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -386,10 +386,11 @@
 // p224Contract converts a FieldElement to its unique, minimal form.
 //
 // On entry, in[i] < 2**29
-// On exit, in[i] < 2**28
+// On exit, out[i] < 2**28 and out < p
 func p224Contract(out, in *p224FieldElement) {
 	copy(out[:], in[:])
 
+	// First, carry the bits above 28 to the higher limb.
 	for i := 0; i < 7; i++ {
 		out[i+1] += out[i] >> 28
 		out[i] &= bottom28Bits
@@ -397,10 +398,13 @@
 	top := out[7] >> 28
 	out[7] &= bottom28Bits
 
+	// Use the reduction identity to carry the overflow.
+	//
+	//   a + top * 2²²⁴ = a + top * 2⁹⁶ - top
 	out[0] -= top
 	out[3] += top << 12
 
-	// We may just have made out[i] negative. So we carry down. If we made
+	// We may just have made out[0] negative. So we carry down. If we made
 	// out[0] negative then we know that out[3] is sufficiently positive
 	// because we just added to it.
 	for i := 0; i < 3; i++ {
@@ -425,13 +429,12 @@
 	// There are two cases to consider for out[3]:
 	//   1) The first time that we eliminated top, we didn't push out[3] over
 	//      2**28. In this case, the partial carry chain didn't change any values
-	//      and top is zero.
+	//      and top is now zero.
 	//   2) We did push out[3] over 2**28 the first time that we eliminated top.
-	//      The first value of top was in [0..16), therefore, prior to eliminating
-	//      the first top, 0xfff1000 <= out[3] <= 0xfffffff. Therefore, after
-	//      overflowing and being reduced by the second carry chain, out[3] <=
-	//      0xf000. Thus it cannot have overflowed when we eliminated top for the
-	//      second time.
+	//      The first value of top was in [0..2], therefore, after overflowing
+	//      and being reduced by the second carry chain, out[3] <= 2<<12 - 1.
+	// In both cases, out[3] cannot have overflowed when we eliminated top for
+	// the second time.
 
 	// Again, we may just have made out[0] negative, so do the same carry down.
 	// As before, if we made out[0] negative then we know that out[3] is
@@ -470,12 +473,11 @@
 	bottom3NonZero |= bottom3NonZero >> 1
 	bottom3NonZero = uint32(int32(bottom3NonZero<<31) >> 31)
 
-	// Everything depends on the value of out[3].
-	//    If it's > 0xffff000 and top4AllOnes != 0 then the whole value is >= p
-	//    If it's = 0xffff000 and top4AllOnes != 0 and bottom3NonZero != 0,
-	//      then the whole value is >= p
+	// Assuming top4AllOnes != 0, everything depends on the value of out[3].
+	//    If it's > 0xffff000 then the whole value is > p
+	//    If it's = 0xffff000 and bottom3NonZero != 0, then the whole value is >= p
 	//    If it's < 0xffff000, then the whole value is < p
-	n := out[3] - 0xffff000
+	n := 0xffff000 - out[3]
 	out3Equal := n
 	out3Equal |= out3Equal >> 16
 	out3Equal |= out3Equal >> 8
@@ -484,8 +486,8 @@
 	out3Equal |= out3Equal >> 1
 	out3Equal = ^uint32(int32(out3Equal<<31) >> 31)
 
-	// If out[3] > 0xffff000 then n's MSB will be zero.
-	out3GT := ^uint32(int32(n) >> 31)
+	// If out[3] > 0xffff000 then n's MSB will be one.
+	out3GT := uint32(int32(n) >> 31)
 
 	mask := top4AllOnes & ((out3Equal & bottom3NonZero) | out3GT)
 	out[0] -= 1 & mask
@@ -494,6 +496,15 @@
 	out[5] -= 0xfffffff & mask
 	out[6] -= 0xfffffff & mask
 	out[7] -= 0xfffffff & mask
+
+	// Do one final carry down, in case we made out[0] negative. One of
+	// out[0..3] needs to be positive and able to absorb the -1 or the value
+	// would have been < p, and the subtraction wouldn't have happened.
+	for i := 0; i < 3; i++ {
+		mask := uint32(int32(out[i]) >> 31)
+		out[i] += (1 << 28) & mask
+		out[i+1] -= 1 & mask
+	}
 }
 
 // Group element functions.
```
