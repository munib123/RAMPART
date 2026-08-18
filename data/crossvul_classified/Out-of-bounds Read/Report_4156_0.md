# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4156_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4156_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 421-461 of the vulnerable file.


// Get common array size, DCHECKing that they all agree.
template <typename ArrayType1, typename ArrayType2>
int MatchingArraySize(const ArrayType1& array1, int index1,
                      const ArrayType2& array2, int index2) {
  TFLITE_DCHECK_EQ(ArraySize(array1, index1), ArraySize(array2, index2));
  return ArraySize(array1, index1);
}

template <typename ArrayType1, typename ArrayType2, typename... Args>
int MatchingArraySize(const ArrayType1& array1, int index1,
                      const ArrayType2& array2, int index2, Args... args) {
  TFLITE_DCHECK_EQ(ArraySize(array1, index1), ArraySize(array2, index2));
  return MatchingArraySize(array1, index1, args...);
}

// Get common shape dim, DCHECKing that they all agree.
inline int MatchingDim(const RuntimeShape& shape1, int index1,
                       const RuntimeShape& shape2, int index2) {
  TFLITE_DCHECK_EQ(shape1.Dims(index1), shape2.Dims(index2));
  return shape1.Dims(index1);
}

template <typename... Args>
int MatchingDim(const RuntimeShape& shape1, int index1,
                const RuntimeShape& shape2, int index2, Args... args) {
  TFLITE_DCHECK_EQ(shape1.Dims(index1), shape2.Dims(index2));
  return MatchingDim(shape1, index1, args...);
}

// Will be phased out with Dims<4>, replaced by RuntimeShape::FlatSize().
template <int N>
inline int FlatSize(const Dims<N>& dims) {
  int flat_size = 1;
  for (int i = 0; i < N; ++i) {
    flat_size *= dims.sizes[i];
  }
  return flat_size;
}

TFLITE_DEPRECATED("Prefer FlatSize.")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -438,7 +438,7 @@
 inline int MatchingDim(const RuntimeShape& shape1, int index1,
                        const RuntimeShape& shape2, int index2) {
   TFLITE_DCHECK_EQ(shape1.Dims(index1), shape2.Dims(index2));
-  return shape1.Dims(index1);
+  return std::min(shape1.Dims(index1), shape2.Dims(index2));
 }
 
 template <typename... Args>
```
