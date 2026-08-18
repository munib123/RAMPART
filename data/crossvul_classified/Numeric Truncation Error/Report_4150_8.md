# CrossVul Fix Pair: Numeric Truncation Error in cpp
**Pair ID:** 4150_8
**Vulnerability Class:** Numeric Truncation Error
**CWE:** CWE-197
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4150_8`)

## Vulnerability Information & PoC

## Description
Numeric Truncation Error - When a primitive is cast to a smaller primitive, the high order bits of the large value are lost in the conversion, potentially resulting in an unexpected value that is not equal to the original va...

## Vulnerable Code
```cpp
Lines 119-159 of the vulnerable file.

      Eigen::array<int, 2> rows_by_one = {static_cast<int>(num_rows), 1};
#endif

      values.device(d) =
          input.maximum(/*dims=*/reduce_on_cols).eval().reshape(rows_by_one);
      // Get the indices of the maximum values.
      for (int r = 0; r < num_rows; ++r) {
        indices(r, 0) = 0;
        for (int c = 0; c < num_cols; ++c) {
          if (values(r, 0) == input(r, c)) {
            indices(r, 0) = c;
            break;
          }
        }
        values(r, 0) = input(r, indices(r, 0));
      }

      return Status::OK();
    }

    auto SortIndices = [&](int start_batch, int limit_batch) {
      for (int32 b = start_batch; b < limit_batch; ++b) {
        const T* input_data = &input(b, 0);
        const auto stable_comp = [input_data](const int32 a, const int32 b) {
          if (input_data[b] < input_data[a]) {
            return true;
          } else if (input_data[b] > input_data[a]) {
            return false;
          } else {
            return a < b;
          }
        };
        const auto comp = [input_data](const int32 a, const int32 b) {
          return input_data[b] < input_data[a];
        };
        // TODO(ebrevdo): For large k < num_cols, instead of using
        // TopN, it may be faster to create a temporary vector of
        // values 0..num_cols - 1 and then use std::partial_sort_copy
        // of this into indices. Choosing the appropriate minimum k or
        // ratio of k/num_cols will require some experimentation.
        if (k == num_cols) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,7 +136,7 @@
       return Status::OK();
     }
 
-    auto SortIndices = [&](int start_batch, int limit_batch) {
+    auto SortIndices = [&](int64 start_batch, int64 limit_batch) {
       for (int32 b = start_batch; b < limit_batch; ++b) {
         const T* input_data = &input(b, 0);
         const auto stable_comp = [input_data](const int32 a, const int32 b) {
```
