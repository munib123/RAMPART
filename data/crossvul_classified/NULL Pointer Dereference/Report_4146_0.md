# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 4146_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4146_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 232-272 of the vulnerable file.

  if (ndim >= 1 && stride_arr[ndim - 1] != 1) {
    return false;
  }
  for (int i = ndim - 2; i >= 0; --i) {
    if (stride_arr[i] != shape_arr[i + 1] * stride_arr[i + 1]) {
      return false;
    }
  }
  return true;
}
}  // namespace

void TFE_CallDLManagedTensorDeleter(void* dlm_ptr) {
  DLManagedTensor* dlMTensor = static_cast<DLManagedTensor*>(dlm_ptr);
  if (dlMTensor->deleter != nullptr) {
    dlMTensor->deleter(dlMTensor);
  }
}

void* TFE_HandleToDLPack(TFE_TensorHandle* h, TF_Status* status) {
  const Tensor* tensor = GetTensorFromHandle(h, status);
  TF_DataType data_type = static_cast<TF_DataType>(tensor->dtype());
  TensorReference tensor_ref(*tensor);  // This will call buf_->Ref()

  auto* tf_dlm_tensor_ctx = new TfDlManagedTensorCtx(tensor_ref);
  tf_dlm_tensor_ctx->reference = tensor_ref;

  DLManagedTensor* dlm_tensor = &tf_dlm_tensor_ctx->tensor;
  dlm_tensor->manager_ctx = tf_dlm_tensor_ctx;
  dlm_tensor->deleter = &DLManagedTensorDeleter;
  dlm_tensor->dl_tensor.ctx = GetDlContext(h, status);
  int ndim = tensor->dims();
  dlm_tensor->dl_tensor.ndim = ndim;
  dlm_tensor->dl_tensor.data = TFE_TensorHandleDevicePointer(h, status);
  dlm_tensor->dl_tensor.dtype = GetDlDataType(data_type, status);

  std::vector<int64_t>* shape_arr = &tf_dlm_tensor_ctx->shape;
  std::vector<int64_t>* stride_arr = &tf_dlm_tensor_ctx->strides;
  shape_arr->resize(ndim);
  stride_arr->resize(ndim, 1);
  for (int i = 0; i < ndim; i++) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -249,21 +249,36 @@
 }
 
 void* TFE_HandleToDLPack(TFE_TensorHandle* h, TF_Status* status) {
+  auto tf_dlm_context = GetDlContext(h, status);
+  if (!status->status.ok()) {
+    return nullptr;
+  }
+
+  auto* tf_dlm_data = TFE_TensorHandleDevicePointer(h, status);
+  if (!status->status.ok()) {
+    return nullptr;
+  }
+
   const Tensor* tensor = GetTensorFromHandle(h, status);
   TF_DataType data_type = static_cast<TF_DataType>(tensor->dtype());
+
+  auto tf_dlm_type = GetDlDataType(data_type, status);
+  if (!status->status.ok()) {
+    return nullptr;
+  }
+
   TensorReference tensor_ref(*tensor);  // This will call buf_->Ref()
-
   auto* tf_dlm_tensor_ctx = new TfDlManagedTensorCtx(tensor_ref);
   tf_dlm_tensor_ctx->reference = tensor_ref;
 
   DLManagedTensor* dlm_tensor = &tf_dlm_tensor_ctx->tensor;
   dlm_tensor->manager_ctx = tf_dlm_tensor_ctx;
   dlm_tensor->deleter = &DLManagedTensorDeleter;
-  dlm_tensor->dl_tensor.ctx = GetDlContext(h, status);
+  dlm_tensor->dl_tensor.ctx = tf_dlm_context;
   int ndim = tensor->dims();
   dlm_tensor->dl_tensor.ndim = ndim;
-  dlm_tensor->dl_tensor.data = TFE_TensorHandleDevicePointer(h, status);
-  dlm_tensor->dl_tensor.dtype = GetDlDataType(data_type, status);
+  dlm_tensor->dl_tensor.data = tf_dlm_data;
+  dlm_tensor->dl_tensor.dtype = tf_dlm_type;
 
   std::vector<int64_t>* shape_arr = &tf_dlm_tensor_ctx->shape;
   std::vector<int64_t>* stride_arr = &tf_dlm_tensor_ctx->strides;
@@ -276,13 +291,14 @@
     (*stride_arr)[i] = (*shape_arr)[i + 1] * (*stride_arr)[i + 1];
   }
 
-  dlm_tensor->dl_tensor.shape = &(*shape_arr)[0];
+  dlm_tensor->dl_tensor.shape = shape_arr->data();
   // There are two ways to represent compact row-major data
   // 1) nullptr indicates tensor is compact and row-majored.
   // 2) fill in the strides array as the real case for compact row-major data.
   // Here we choose option 2, since some frameworks didn't handle the strides
   // argument properly.
-  dlm_tensor->dl_tensor.strides = &(*stride_arr)[0];
+  dlm_tensor->dl_tensor.strides = stride_arr->data();
+
   dlm_tensor->dl_tensor.byte_offset =
       0;  // TF doesn't handle the strides and byte_offsets here
   return static_cast<void*>(dlm_tensor);
```
