# CrossVul Fix Pair: Numeric Truncation Error in cpp
**Pair ID:** 4150_1
**Vulnerability Class:** Numeric Truncation Error
**CWE:** CWE-197
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4150_1`)

## Vulnerability Information & PoC

## Description
Numeric Truncation Error - When a primitive is cast to a smaller primitive, the high order bits of the large value are lost in the conversion, potentially resulting in an unexpected value that is not equal to the original va...

## Vulnerable Code
```cpp
Lines 206-246 of the vulnerable file.

// Partial specialization of CropAndResize functor for a CPUDevice.
namespace functor {
template <typename T>
struct CropAndResize<CPUDevice, T> {
  bool operator()(const OpKernelContext* context,
                  typename TTypes<T, 4>::ConstTensor image,
                  typename TTypes<float, 2>::ConstTensor boxes,
                  typename TTypes<int32, 1>::ConstTensor box_index,
                  const string& method_name, float extrapolation_value,
                  typename TTypes<float, 4>::Tensor crops) {
    const int batch_size = image.dimension(0);
    const int image_height = image.dimension(1);
    const int image_width = image.dimension(2);

    const int num_boxes = crops.dimension(0);
    const int crop_height = crops.dimension(1);
    const int crop_width = crops.dimension(2);
    const int depth = crops.dimension(3);

    // Sharding across boxes.
    auto CropAndResizePerBox = [&](int start_box, int limit_box) {
      for (int b = start_box; b < limit_box; ++b) {
        const float y1 = boxes(b, 0);
        const float x1 = boxes(b, 1);
        const float y2 = boxes(b, 2);
        const float x2 = boxes(b, 3);

        const int32 b_in = box_index(b);
        if (!FastBoundsCheck(b_in, batch_size)) {
          continue;
        }

        const float height_scale =
            (crop_height > 1)
                ? (y2 - y1) * (image_height - 1) / (crop_height - 1)
                : 0;
        const float width_scale =
            (crop_width > 1) ? (x2 - x1) * (image_width - 1) / (crop_width - 1)
                             : 0;

        for (int y = 0; y < crop_height; ++y) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -223,7 +223,7 @@
     const int depth = crops.dimension(3);
 
     // Sharding across boxes.
-    auto CropAndResizePerBox = [&](int start_box, int limit_box) {
+    auto CropAndResizePerBox = [&](int64 start_box, int64 limit_box) {
       for (int b = start_box; b < limit_box; ++b) {
         const float y1 = boxes(b, 0);
         const float x1 = boxes(b, 1);
@@ -449,7 +449,7 @@
 
     grads_image.setZero();
 
-    auto CropAndResizeBackImgPerBox = [&](int start_box, int limit_box) {
+    auto CropAndResizeBackImgPerBox = [&](int64 start_box, int64 limit_box) {
       for (int b = start_box; b < limit_box; ++b) {
         const float y1 = boxes(b, 0);
         const float x1 = boxes(b, 1);
```
