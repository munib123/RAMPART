# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4524_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4524_2`)

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

#include "tensorflow/python/lib/core/py_seq_tensor.h"

#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_shape.h"
#include "tensorflow/core/framework/types.h"
#include "tensorflow/core/lib/core/errors.h"
#include "tensorflow/core/lib/core/stringpiece.h"
#include "tensorflow/core/lib/strings/str_util.h"
#include "tensorflow/core/platform/types.h"
#include "tensorflow/python/lib/core/numpy.h"
#include "tensorflow/python/lib/core/py_util.h"
#include "tensorflow/python/lib/core/safe_ptr.h"

namespace tensorflow {
namespace {

inline bool PyIsInstance(PyObject* obj, PyTypeObject* t) {
  return PyObject_IsInstance(obj, reinterpret_cast<PyObject*>(t));
}

inline PyObject* PyType(PyObject* obj) {
  return reinterpret_cast<PyObject*>(obj->ob_type);
}

bool IsPyString(PyObject* obj) {
  return PyBytes_Check(obj) || PyUnicode_Check(obj);
}

bool IsPyInt(PyObject* obj) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
 #include "tensorflow/core/lib/core/errors.h"
 #include "tensorflow/core/lib/core/stringpiece.h"
 #include "tensorflow/core/lib/strings/str_util.h"
+#include "tensorflow/core/platform/macros.h"
 #include "tensorflow/core/platform/types.h"
 #include "tensorflow/python/lib/core/numpy.h"
 #include "tensorflow/python/lib/core/py_util.h"
@@ -396,6 +397,21 @@
 
 // Floating-point support
 
+// Returns `true` if `out` overflows when converted from `as_double`.
+template <class T>
+static inline bool CheckForOverflow(double as_double, T* out) {
+  return (sizeof(T) < sizeof(double) && std::isinf(*out) &&
+          std::isfinite(as_double));
+}
+
+// There is no `std::isinf` that takes `Eigen::half` as argument but Eigen
+// provides `Eigen::half_impl::isinf` instead.
+template <>
+inline bool CheckForOverflow<Eigen::half>(double as_double, Eigen::half* out) {
+  return (sizeof(Eigen::half) < sizeof(double) &&
+          Eigen::half_impl::isinf(*out) && std::isfinite(as_double));
+}
+
 template <class T>
 static const char* ConvertOneFloat(PyObject* v, T* out) {
   if (PyErr_Occurred()) {
@@ -405,20 +421,19 @@
     const double as_double = PyFloat_AS_DOUBLE(v);
     *out = static_cast<T>(as_double);
     // Check for overflow
-    if (TF_PREDICT_FALSE(sizeof(T) < sizeof(double) && std::isinf(*out) &&
-                         std::isfinite(as_double))) {
+    if (TF_PREDICT_FALSE(CheckForOverflow<T>(as_double, out))) {
       return ErrorOutOfRangeDouble;
     }
     return nullptr;
   }
 #if PY_MAJOR_VERSION < 3
   if (PyInt_Check(v)) {
-    *out = PyInt_AS_LONG(v);
+    *out = static_cast<T>(PyInt_AS_LONG(v));
     return nullptr;
   }
 #endif
   if (PyLong_Check(v)) {
-    *out = PyLong_AsDouble(v);
+    *out = static_cast<T>(PyLong_AsDouble(v));
     if (PyErr_Occurred()) return ErrorOutOfRangeDouble;
     return nullptr;
   }
@@ -467,13 +482,7 @@
   static const tensorflow::DataType kTypeEnum = DT_HALF;
 
   static const char* ConvertScalar(PyObject* v, Eigen::half* out) {
-    // NOTE(nareshmodi): Is there a way to convert to C double without the
-    // intermediate Python double? This will help with ConvertOneFloat as well.
-    Safe_PyObjectPtr as_float = make_safe(PyNumber_Float(v));
-    double v_double = PyFloat_AS_DOUBLE(as_float.get());
-    *out = Eigen::half(v_double);
-
-    return nullptr;
+    return ConvertOneFloat<Eigen::half>(v, out);
   }
 };
 
@@ -613,7 +622,9 @@
       break;
 
     case DT_HALF:
-      RETURN_STRING_AS_STATUS(NumpyHalfConverter::Convert(obj, &state, ret));
+      if (NumpyHalfConverter::Convert(obj, &state, ret) == nullptr)
+        return Status::OK();
+      break;
 
     case DT_INT64:
       if (Int64Converter::Convert(obj, &state, ret) == nullptr)
```
