# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 4201_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4201_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 53-93 of the vulnerable file.


typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;
using Callback = std::function<void()>;

static inline Status ParseAndCheckBoxSizes(const Tensor& boxes,
                                           const Tensor& box_index,
                                           int* num_boxes) {
  if (boxes.NumElements() == 0 && box_index.NumElements() == 0) {
    *num_boxes = 0;
    return Status::OK();
  }
  // The shape of 'boxes' is [num_boxes, 4].
  if (boxes.dims() != 2) {
    return errors::InvalidArgument("boxes must be 2-D",
                                   boxes.shape().DebugString());
  }
  *num_boxes = boxes.dim_size(0);
  if (boxes.dim_size(1) != 4) {
    return errors::InvalidArgument("boxes must have 4 columns");
  }
  // The shape of 'box_index' is [num_boxes].
  if (box_index.dims() != 1) {
    return errors::InvalidArgument("box_index must be 1-D",
                                   box_index.shape().DebugString());
  }
  if (box_index.dim_size(0) != *num_boxes) {
    return errors::InvalidArgument("box_index has incompatible shape");
  }
  return Status::OK();
}

// Conditionally calls the compute callback if all values in box_index are in
// [0, batch_size) then calls done.
template <typename Device>
inline void RunIfBoxIndexIsValid(
    OpKernelContext* context, typename TTypes<int32, 1>::ConstTensor box_index,
    int batch_size, const Callback& compute, const Callback& done);

// Specialization of CheckValidBoxIndex for a CPUDevice.
template <>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,6 +70,18 @@
   *num_boxes = boxes.dim_size(0);
   if (boxes.dim_size(1) != 4) {
     return errors::InvalidArgument("boxes must have 4 columns");
+  }
+  for (int64 i = 0; i < *num_boxes; i++) {
+    for (int64 j = 0; j < 4; j++) {
+      if (!isfinite(boxes.tensor<float, 2>()(i, j))) {
+        return errors::InvalidArgument(
+            "boxes values must be finite, received boxes[", i, "]: ",
+            boxes.tensor<float, 2>()(i, 0), ", ",
+            boxes.tensor<float, 2>()(i, 1), ", ",
+            boxes.tensor<float, 2>()(i, 2), ", ",
+            boxes.tensor<float, 2>()(i, 3));
+      }
+    }
   }
   // The shape of 'box_index' is [num_boxes].
   if (box_index.dims() != 1) {
@@ -256,6 +268,7 @@
             continue;
           }
           if (method_name == "bilinear") {
+
             const int top_y_index = floorf(in_y);
             const int bottom_y_index = ceilf(in_y);
             const float y_lerp = in_y - top_y_index;
```
