# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 4146_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4146_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 1341-1381 of the vulnerable file.


  // TFE_CancellationManager Logic
  m.def("TFE_NewCancellationManager", &TFE_NewCancellationManager,
        py::return_value_policy::reference);
  m.def("TFE_CancellationManagerIsCancelled",
        &TFE_CancellationManagerIsCancelled);
  m.def("TFE_CancellationManagerStartCancel",
        &TFE_CancellationManagerStartCancel);
  m.def("TFE_DeleteCancellationManager", &TFE_DeleteCancellationManager,
        py::return_value_policy::reference);

  m.def("TFE_ClearScalarCache", &tensorflow::TFE_ClearScalarCache);

  // Util buffer helper functions
  m.def("TF_NewBufferFromString", &TF_NewBufferFromString,
        py::return_value_policy::reference);

  // DLPack functions
  m.def("TFE_ToDlpackCapsule", [](py::handle& o) {
    PyObject* eager_tensor_pyobject_ptr = o.ptr();
    TFE_TensorHandle* thandle = EagerTensor_Handle(eager_tensor_pyobject_ptr);
    tensorflow::Safe_TF_StatusPtr status =
        tensorflow::make_safe(TF_NewStatus());
    void* dlm_ptr = tensorflow::TFE_HandleToDLPack(thandle, status.get());
    tensorflow::MaybeRaiseRegisteredFromTFStatus(status.get());

    py::capsule capsule(
        dlm_ptr, tensorflow::kDlTensorCapsuleName, [](PyObject* capsule) {
          if (PyCapsule_IsValid(capsule, tensorflow::kDlTensorCapsuleName)) {
            void* dlm_rptr =
                PyCapsule_GetPointer(capsule, tensorflow::kDlTensorCapsuleName);
            if (dlm_rptr) {
              tensorflow::TFE_CallDLManagedTensorDeleter(dlm_rptr);
              PyCapsule_SetDestructor(capsule, nullptr);
            }
          }
        });
    return capsule;
  });

  m.def("TFE_FromDlpackCapsule", [](const py::capsule& pycapsule,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1358,9 +1358,16 @@
   // DLPack functions
   m.def("TFE_ToDlpackCapsule", [](py::handle& o) {
     PyObject* eager_tensor_pyobject_ptr = o.ptr();
+    tensorflow::Safe_TF_StatusPtr status =
+        tensorflow::make_safe(TF_NewStatus());
+
+    if (!EagerTensor_CheckExact(eager_tensor_pyobject_ptr)) {
+      status->status = tensorflow::errors::InvalidArgument(
+          "The argument to `to_dlpack` must be a TF tensor, not Python object");
+      tensorflow::MaybeRaiseRegisteredFromTFStatus(status.get());
+    }
+
     TFE_TensorHandle* thandle = EagerTensor_Handle(eager_tensor_pyobject_ptr);
-    tensorflow::Safe_TF_StatusPtr status =
-        tensorflow::make_safe(TF_NewStatus());
     void* dlm_ptr = tensorflow::TFE_HandleToDLPack(thandle, status.get());
     tensorflow::MaybeRaiseRegisteredFromTFStatus(status.get());
 
```
