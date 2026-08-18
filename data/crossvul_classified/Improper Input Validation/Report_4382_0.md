# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4382_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4382_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 1451-1491 of the vulnerable file.

                                   int batch_size, int data_size,
                                   cudnnDataType_t data_type,
                                   RNNDataDescriptor data_handle,
                                   TensorDescriptor handle)
      : max_seq_length_(max_seq_length),
        batch_size_(batch_size),
        data_size_(data_size),
        data_type_(data_type),
        handle_(std::move(handle)),
        rnn_data_handle_(std::move(data_handle)),
        handles_(max_seq_length, handle_.get()) {
  }

 public:
  CudnnRnnSequenceTensorDescriptor(CudnnRnnSequenceTensorDescriptor&&) =
      default;

  static port::StatusOr<CudnnRnnSequenceTensorDescriptor> Create(
      GpuExecutor* parent, int max_seq_length, int batch_size, int data_size,
      cudnnDataType_t data_type) {
    CHECK_GT(max_seq_length, 0);
    int dims[] = {batch_size, data_size, 1};
    int strides[] = {dims[1] * dims[2], dims[2], 1};
    TensorDescriptor tensor_desc = CreateTensorDescriptor();
    RETURN_IF_CUDNN_ERROR(cudnnSetTensorNdDescriptor(
        /*tensorDesc=*/tensor_desc.get(), /*dataType=*/data_type,
        /*nbDims=*/sizeof(dims) / sizeof(dims[0]), /*dimA=*/dims,
        /*strideA=*/strides));
    return CudnnRnnSequenceTensorDescriptor(parent, max_seq_length, batch_size,
                                            data_size, data_type,
                                            nullptr,
                                            std::move(tensor_desc));
  }

  static port::StatusOr<CudnnRnnSequenceTensorDescriptor> Create(
      GpuExecutor* parent, int max_seq_length, int batch_size, int data_size,
      const absl::Span<const int>& seq_lengths, bool time_major,
      cudnnDataType_t data_type) {
    CHECK_GT(max_seq_length, 0);
    int dims[] = {batch_size, data_size, 1};
    int strides[] = {dims[1] * dims[2], dims[2], 1};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1468,7 +1468,9 @@
   static port::StatusOr<CudnnRnnSequenceTensorDescriptor> Create(
       GpuExecutor* parent, int max_seq_length, int batch_size, int data_size,
       cudnnDataType_t data_type) {
-    CHECK_GT(max_seq_length, 0);
+    if (max_seq_length <= 0) {
+      return port::Status(port::error::INVALID_ARGUMENT, "max_seq_length <= 0");
+    }
     int dims[] = {batch_size, data_size, 1};
     int strides[] = {dims[1] * dims[2], dims[2], 1};
     TensorDescriptor tensor_desc = CreateTensorDescriptor();
@@ -1486,7 +1488,9 @@
       GpuExecutor* parent, int max_seq_length, int batch_size, int data_size,
       const absl::Span<const int>& seq_lengths, bool time_major,
       cudnnDataType_t data_type) {
-    CHECK_GT(max_seq_length, 0);
+    if (max_seq_length <= 0) {
+      return port::Status(port::error::INVALID_ARGUMENT, "max_seq_length <= 0");
+    }
     int dims[] = {batch_size, data_size, 1};
     int strides[] = {dims[1] * dims[2], dims[2], 1};
     TensorDescriptor tensor_desc = CreateTensorDescriptor();
```
