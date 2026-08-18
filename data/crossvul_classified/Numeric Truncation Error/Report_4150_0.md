# CrossVul Fix Pair: Numeric Truncation Error in cpp
**Pair ID:** 4150_0
**Vulnerability Class:** Numeric Truncation Error
**CWE:** CWE-197
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4150_0`)

## Vulnerability Information & PoC

## Description
Numeric Truncation Error - When a primitive is cast to a smaller primitive, the high order bits of the large value are lost in the conversion, potentially resulting in an unexpected value that is not equal to the original va...

## Vulnerable Code
```cpp
Lines 104-144 of the vulnerable file.


    Tensor* output_node_ids_t = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output("node_ids", {batch_size},
                                                     &output_node_ids_t));
    auto output_node_ids = output_node_ids_t->vec<int32>();

    // Indicate that the latest tree was used.
    const int32 latest_tree = resource->num_trees() - 1;

    if (latest_tree < 0) {
      // Ensemble was empty. Output the very first node.
      output_node_ids.setZero();
      output_tree_ids = cached_tree_ids;
      // All the predictions are zeros.
      output_partial_logits.setZero();
    } else {
      output_tree_ids.setConstant(latest_tree);
      auto do_work = [&resource, &bucketized_features, &cached_tree_ids,
                      &cached_node_ids, &output_partial_logits,
                      &output_node_ids, latest_tree,
                      this](int32 start, int32 end) {
        for (int32 i = start; i < end; ++i) {
          int32 tree_id = cached_tree_ids(i);
          int32 node_id = cached_node_ids(i);
          std::vector<float> partial_tree_logits(logits_dimension_, 0.0);

          if (node_id >= 0) {
            // If the tree was pruned, returns the node id into which the
            // current_node_id was pruned, as well the correction of the cached
            // logit prediction.
            resource->GetPostPruneCorrection(tree_id, node_id, &node_id,
                                             &partial_tree_logits);
            // Logic in the loop adds the cached node value again if it is a
            // leaf. If it is not a leaf anymore we need to subtract the old
            // node's value. The following logic handles both of these cases.
            const auto& node_logits = resource->node_value(tree_id, node_id);
            if (!node_logits.empty()) {
              DCHECK_EQ(node_logits.size(), logits_dimension_);
              for (int32 j = 0; j < logits_dimension_; ++j) {
                partial_tree_logits[j] -= node_logits[j];
              }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,7 +121,7 @@
       auto do_work = [&resource, &bucketized_features, &cached_tree_ids,
                       &cached_node_ids, &output_partial_logits,
                       &output_node_ids, latest_tree,
-                      this](int32 start, int32 end) {
+                      this](int64 start, int64 end) {
         for (int32 i = start; i < end; ++i) {
           int32 tree_id = cached_tree_ids(i);
           int32 node_id = cached_node_ids(i);
@@ -237,7 +237,7 @@
 
     const int32 last_tree = resource->num_trees() - 1;
     auto do_work = [&resource, &bucketized_features, &output_logits, last_tree,
-                    this](int32 start, int32 end) {
+                    this](int64 start, int64 end) {
       for (int32 i = start; i < end; ++i) {
         std::vector<float> tree_logits(logits_dimension_, 0.0);
         int32 tree_id = 0;
@@ -340,7 +340,7 @@
     // path. Note: feature_ids has one less value than logits_path because the
     // first value of each logit path will be the bias.
     auto do_work = [&resource, &bucketized_features, &output_debug_info,
-                    last_tree](int32 start, int32 end) {
+                    last_tree](int64 start, int64 end) {
       for (int32 i = start; i < end; ++i) {
         // Proto to store debug outputs, per example.
         boosted_trees::DebugOutput example_debug_info;
```
