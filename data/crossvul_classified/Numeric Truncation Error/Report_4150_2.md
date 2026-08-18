# CrossVul Fix Pair: Numeric Truncation Error in cpp
**Pair ID:** 4150_2
**Vulnerability Class:** Numeric Truncation Error
**CWE:** CWE-197
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4150_2`)

## Vulnerability Information & PoC

## Description
Numeric Truncation Error - When a primitive is cast to a smaller primitive, the high order bits of the large value are lost in the conversion, potentially resulting in an unexpected value that is not equal to the original va...

## Vulnerable Code
```cpp
Lines 176-216 of the vulnerable file.


    using Matrix =
        Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic, Eigen::RowMajor>;
    using ConstMatrixMap = Eigen::Map<const Matrix>;
    using RealScalar = typename Eigen::NumTraits<Scalar>::Real;
    // Check diagonal before doing any solves. This is the first row in the
    // lower case and else is the last row.
    auto matrix = ConstMatrixMap(in_x.flat<Scalar>().data(), in_x.dim_size(1),
                                 in_x.dim_size(2));
    RealScalar min_abs_pivot;
    if (lower) {
      min_abs_pivot = matrix.row(0).cwiseAbs().minCoeff();
    } else {
      min_abs_pivot = matrix.row(in_x.dim_size(1) - 1).cwiseAbs().minCoeff();
    }
    OP_REQUIRES(context, min_abs_pivot > RealScalar(0),
                errors::InvalidArgument("Input matrix is not invertible."));

    Shard(worker_threads.num_threads, worker_threads.workers, batch_size,
          cost_per_unit,
          [&in_x, &in_y, adjoint, lower, &bcast, out](int start, int limit) {
            SequentialBandedTriangularSolveKernel<Scalar>::Run(
                in_x, in_y, lower, adjoint, bcast, out, start, limit);
          });
  }
};

template <typename Scalar>
class BandedTriangularSolveOpCpu : public OpKernel {
 public:
  explicit BandedTriangularSolveOpCpu(OpKernelConstruction* context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("lower", &lower_));
    OP_REQUIRES_OK(context, context->GetAttr("adjoint", &adjoint_));
  }

  ~BandedTriangularSolveOpCpu() override {}

  void Compute(OpKernelContext* ctx) override {
    const Tensor& in0 = ctx->input(0);
    const Tensor& in1 = ctx->input(1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -193,7 +193,8 @@
 
     Shard(worker_threads.num_threads, worker_threads.workers, batch_size,
           cost_per_unit,
-          [&in_x, &in_y, adjoint, lower, &bcast, out](int start, int limit) {
+          [&in_x, &in_y, adjoint, lower, &bcast, out](int64 start,
+                                                      int64 limit) {
             SequentialBandedTriangularSolveKernel<Scalar>::Run(
                 in_x, in_y, lower, adjoint, bcast, out, start, limit);
           });
```
