# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4383_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4383_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 27-67 of the vulnerable file.

#include "absl/strings/str_cat.h"
#include "tensorflow/core/common_runtime/shape_refiner.h"
#include "tensorflow/core/framework/function.h"
#include "tensorflow/core/framework/function.pb.h"
#include "tensorflow/core/framework/graph.pb.h"
#include "tensorflow/core/framework/node_def.pb.h"
#include "tensorflow/core/framework/node_def_util.h"
#include "tensorflow/core/framework/tensor_shape.pb.h"
#include "tensorflow/core/framework/types.h"
#include "tensorflow/core/framework/versions.h"
#include "tensorflow/core/framework/versions.pb.h"
#include "tensorflow/core/graph/algorithm.h"
#include "tensorflow/core/graph/graph.h"
#include "tensorflow/core/graph/tensor_id.h"
#include "tensorflow/core/lib/core/errors.h"
#include "tensorflow/core/lib/gtl/flatmap.h"
#include "tensorflow/core/lib/gtl/flatset.h"
#include "tensorflow/core/lib/gtl/inlined_vector.h"
#include "tensorflow/core/lib/strings/scanner.h"
#include "tensorflow/core/lib/strings/str_util.h"
#include "tensorflow/core/platform/logging.h"
#include "tensorflow/core/platform/macros.h"
#include "tensorflow/core/public/version.h"

namespace tensorflow {

namespace {

// We remove duplicate control inputs before adding edges to the Graph, so we
// can skip expensive duplicates check in 'AddControlEdge'.
static constexpr const bool kDoNotCheckDuplicates = true;

inline bool IsMerge(const NodeDef& node_def) {
  return node_def.op() == "Merge" || node_def.op() == "RefMerge" ||
         node_def.op() == "_XlaMerge";
}

inline bool IsNextIteration(const NodeDef& node_def) {
  return node_def.op() == "NextIteration" ||
         node_def.op() == "RefNextIteration";
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,6 +44,7 @@
 #include "tensorflow/core/lib/gtl/inlined_vector.h"
 #include "tensorflow/core/lib/strings/scanner.h"
 #include "tensorflow/core/lib/strings/str_util.h"
+#include "tensorflow/core/platform/errors.h"
 #include "tensorflow/core/platform/logging.h"
 #include "tensorflow/core/platform/macros.h"
 #include "tensorflow/core/public/version.h"
@@ -1425,6 +1426,17 @@
 
 Status GraphConstructor::MakeEdge(Node* src, int output_index, Node* dst,
                                   int input_index) {
+  if (output_index >= src->num_outputs()) {
+    return errors::InvalidArgument(
+        "Output ", output_index, " of node ", src->name(),
+        " does not exist. Node only has ", src->num_outputs(), " outputs.");
+  }
+  if (input_index >= dst->num_inputs()) {
+    return errors::InvalidArgument(
+        "Input ", input_index, " of node ", dst->name(),
+        " does not exist. Node only has ", dst->num_inputs(), " inputs.");
+  }
+
   DataType src_out = src->output_type(output_index);
   DataType dst_in = dst->input_type(input_index);
   if (!TypesCompatible(dst_in, src_out)) {
```
