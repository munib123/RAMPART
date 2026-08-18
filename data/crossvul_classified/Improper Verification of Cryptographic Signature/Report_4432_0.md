# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in csharp
**Pair ID:** 4432_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4432_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```csharp
Lines 217-257 of the vulnerable file.

            foreach (var value in values)
            {
                if (!string.IsNullOrEmpty(value)) return value;
            }
            return null;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static T FirstNonDefault<T>(this IEnumerable<T> values)
        {
            foreach (var value in values)
            {
                if (!Equals(value, default(T))) return value;
            }
            return default(T);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool EquivalentTo(this byte[] bytes, byte[] other)
        {
            var compare = 0;
            for (var i = 0; i < other.Length; i++)
                compare |= other[i] ^ bytes[i];

            return compare == 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool EquivalentTo<T>(this T[] array, T[] otherArray, Func<T, T, bool> comparer = null)
        {
            if (array == null || otherArray == null)
                return array == otherArray;

            if (array.Length != otherArray.Length)
                return false;

            if (comparer == null)
                comparer = (v1, v2) => v1.Equals(v2);

            for (var i = 0; i < array.Length; i++)
            {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -234,6 +234,12 @@
         [MethodImpl(MethodImplOptions.AggressiveInlining)]
         public static bool EquivalentTo(this byte[] bytes, byte[] other)
         {
+            if (bytes == null || other == null)
+                return bytes == other;
+
+            if (bytes.Length != other.Length)
+                return false;
+
             var compare = 0;
             for (var i = 0; i < other.Length; i++)
                 compare |= other[i] ^ bytes[i];
```
