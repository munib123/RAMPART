# CrossVul Fix Pair: Heap-based Buffer Overflow in cpp
**Pair ID:** 4153_0
**Vulnerability Class:** Heap-based Buffer Overflow
**CWE:** CWE-122
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4153_0`)

## Vulnerability Information & PoC

## Description
Heap-based Buffer Overflow - A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally meaning that the buffer was allocated using a routine ...

## Vulnerable Code
```cpp
Lines 2-42 of the vulnerable file.


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/

#include <locale>
#include <string>

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "tensorflow/core/framework/op_kernel.h"

namespace tensorflow {
namespace text {

namespace {
template <typename SPLITS_TYPE>
class StringNGramsOp : public tensorflow::OpKernel {
 public:
  explicit StringNGramsOp(tensorflow::OpKernelConstruction* context)
      : tensorflow::OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("separator", &separator_));
    OP_REQUIRES_OK(context, context->GetAttr("ngram_widths", &ngram_widths_));
    OP_REQUIRES_OK(context, context->GetAttr("left_pad", &left_pad_));
    OP_REQUIRES_OK(context, context->GetAttr("right_pad", &right_pad_));
    OP_REQUIRES_OK(context, context->GetAttr("pad_width", &pad_width_));
    OP_REQUIRES_OK(context, context->GetAttr("preserve_short_sequences",
                                             &preserve_short_));
  }

  int get_pad_width(const int ngram_width) const {
    // Ngrams can be padded with either a fixed pad width or a dynamic pad
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 #include "absl/strings/ascii.h"
 #include "absl/strings/str_cat.h"
 #include "tensorflow/core/framework/op_kernel.h"
+#include "tensorflow/core/platform/errors.h"
 
 namespace tensorflow {
 namespace text {
@@ -59,6 +60,18 @@
     const tensorflow::Tensor* splits;
     OP_REQUIRES_OK(context, context->input("data_splits", &splits));
     const auto& splits_vec = splits->flat<SPLITS_TYPE>();
+
+    // Validate that the splits are valid indices into data
+    const int input_data_size = data->flat<tstring>().size();
+    const int splits_vec_size = splits_vec.size();
+    for (int i = 0; i < splits_vec_size; ++i) {
+      bool valid_splits = splits_vec(i) >= 0;
+      valid_splits = valid_splits && (splits_vec(i) <= input_data_size);
+      OP_REQUIRES(
+          context, valid_splits,
+          errors::InvalidArgument("Invalid split value ", splits_vec(i),
+                                  ", must be in [0,", input_data_size, "]"));
+    }
 
     int num_batch_items = splits_vec.size() - 1;
     tensorflow::Tensor* ngrams_splits;
```
