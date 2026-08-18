# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 4145_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4145_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 291-331 of the vulnerable file.

    port::ScopedFlushDenormal flush;
    port::ScopedSetRound round(FE_TONEAREST);
    // 'AnnotatedTraceMe' will trace both scheduling time on host and execution
    // time on device of the OpKernel.
    profiler::AnnotatedTraceMe activity(
        [&] { return kernel_->TraceString(context, /*verbose=*/false); },
        profiler::TraceMeLevel::kInfo);
    device_->Compute(kernel_.get(), &context);
  }

  // Clean up execution op_execution_state if deferred ops aren't running.
  if (op_execution_state != nullptr) {
    op_execution_state->Unref();
  }

  if (!context.status().ok()) return context.status();

  if (outputs != nullptr) {
    outputs->clear();
    for (int i = 0; i < context.num_outputs(); ++i) {
      outputs->push_back(Tensor(*context.mutable_output(i)));
    }
  }
  return Status::OK();
}

Status KernelAndDeviceFunc::Run(
    ScopedStepContainer* step_container, const EagerKernelArgs& inputs,
    std::vector<EagerKernelRet>* outputs,
    CancellationManager* cancellation_manager,
    const absl::optional<EagerRemoteFunctionParams>& remote_func_params) {
  Notification n;
  Status status;
  RunAsync(step_container, inputs, outputs, cancellation_manager,
           remote_func_params, [&status, &n](const Status& s) {
             status = s;
             n.Notify();
           });
  n.WaitForNotification();
  return status;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -308,7 +308,12 @@
   if (outputs != nullptr) {
     outputs->clear();
     for (int i = 0; i < context.num_outputs(); ++i) {
-      outputs->push_back(Tensor(*context.mutable_output(i)));
+      const auto* output_tensor = context.mutable_output(i);
+      if (output_tensor != nullptr) {
+        outputs->push_back(Tensor(*output_tensor));
+      } else {
+        outputs->push_back(Tensor());
+      }
     }
   }
   return Status::OK();
```
