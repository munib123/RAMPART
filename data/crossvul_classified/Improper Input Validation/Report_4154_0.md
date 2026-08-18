# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4154_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4154_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 4-44 of the vulnerable file.

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/

#include "tensorflow/cc/saved_model/loader.h"

#include <unordered_set>

#include "tensorflow/cc/saved_model/constants.h"
#include "tensorflow/cc/saved_model/loader_util.h"
#include "tensorflow/cc/saved_model/reader.h"
#include "tensorflow/core/framework/attr_value.pb.h"
#include "tensorflow/core/framework/node_def.pb.h"
#include "tensorflow/core/framework/tensor.pb.h"
#include "tensorflow/core/lib/io/path.h"
#include "tensorflow/core/lib/monitoring/counter.h"
#include "tensorflow/core/lib/monitoring/sampler.h"
#include "tensorflow/core/lib/strings/str_util.h"
#include "tensorflow/core/lib/strings/strcat.h"
#include "tensorflow/core/platform/env.h"
#include "tensorflow/core/platform/errors.h"
#include "tensorflow/core/protobuf/graph_debug_info.pb.h"
#include "tensorflow/core/protobuf/meta_graph.pb.h"
#include "tensorflow/core/protobuf/saver.pb.h"
#include "tensorflow/core/public/session.h"
#include "tensorflow/core/public/session_options.h"
#include "tensorflow/core/util/tensor_bundle/naming.h"

namespace tensorflow {
namespace {

auto* load_attempt_count = monitoring::Counter<2>::New(
    "/tensorflow/cc/saved_model/load_attempt_count",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
 #include "tensorflow/cc/saved_model/loader_util.h"
 #include "tensorflow/cc/saved_model/reader.h"
 #include "tensorflow/core/framework/attr_value.pb.h"
+#include "tensorflow/core/framework/function.pb.h"
 #include "tensorflow/core/framework/node_def.pb.h"
 #include "tensorflow/core/framework/tensor.pb.h"
 #include "tensorflow/core/lib/io/path.h"
@@ -73,26 +74,41 @@
 // Ensure that constant tensors loaded from the saved model have valid shape.
 // Also ensure that constant nodes have a value assigned to them.
 // TODO(b/154763635): this is temporary and will be replaced with a better audit
+static Status ValidateNode(const NodeDef& node) {
+  const auto node_iterator = node.attr().find("value");
+  if (node_iterator != node.attr().end()) {
+    AttrValue node_value = node_iterator->second;
+    if (node_value.has_tensor()) {
+      const PartialTensorShape node_shape(node_value.tensor().tensor_shape());
+      if (node_shape.num_elements() < 0) {
+        return errors::FailedPrecondition(
+            "Saved model contains node \"", node.name(), "\" (op \"", node.op(),
+            "\") which initializes from a tensor with ",
+            node_shape.num_elements(), " elements");
+      }
+    }
+  } else if (node.op() == "Const") {
+    return errors::FailedPrecondition(
+        "Saved model contains node \"", node.name(),
+        "\" which is a constant tensor but no value has been provided");
+  }
+  return Status::OK();
+}
+
 static Status ValidateSavedTensors(const GraphDef& graph_def) {
   for (const auto& node : graph_def.node()) {
-    const auto node_iterator = node.attr().find("value");
-    if (node_iterator != node.attr().end()) {
-      AttrValue node_value = node_iterator->second;
-      if (node_value.has_tensor()) {
-        const PartialTensorShape node_shape(node_value.tensor().tensor_shape());
-        if (node_shape.num_elements() < 0) {
-          return errors::FailedPrecondition(
-              "Saved model contains node \"", node.name(), "\" (op \"",
-              node.op(), "\") which initializes from a tensor with ",
-              node_shape.num_elements(), " elements");
-        }
+    TF_RETURN_IF_ERROR(ValidateNode(node));
+  }
+
+  if (graph_def.has_library()) {
+    const FunctionDefLibrary& library = graph_def.library();
+    for (const auto& function : library.function()) {
+      for (const auto& node : function.node_def()) {
+        TF_RETURN_IF_ERROR(ValidateNode(node));
       }
-    } else if (node.op() == "Const") {
-      return errors::FailedPrecondition(
-          "Saved model contains node \"", node.name(),
-          "\" which is a constant tensor but no value has been provided");
     }
   }
+
   return Status::OK();
 }
 
```
