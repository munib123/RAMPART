# CrossVul Fix Pair: Use After Free in cpp
**Pair ID:** 816_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `816_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```cpp
Lines 559-599 of the vulnerable file.

            return Error(heif_error_Invalid_input,
                         heif_suberror_Auxiliary_image_type_unspecified,
                         sstr.str());
          }

          std::vector<heif_item_id> refs = ref.to_item_ID;
          if (refs.size() != 1) {
            return Error(heif_error_Invalid_input,
                         heif_suberror_Unspecified,
                         "Too many auxiliary image references");
          }


          // alpha channel

          if (auxC_property->get_aux_type() == "urn:mpeg:avc:2015:auxid:1" ||
              auxC_property->get_aux_type() == "urn:mpeg:hevc:2015:auxid:1") {
            image->set_is_alpha_channel_of(refs[0]);

            auto master_iter = m_all_images.find(refs[0]);
            if (image.get() == master_iter->second.get()) {
              return Error(heif_error_Invalid_input,
                           heif_suberror_Nonexisting_item_referenced,
                           "Recursive alpha image detected");
            }
            master_iter->second->set_alpha_channel(image);
          }


          // depth channel

          if (auxC_property->get_aux_type() == "urn:mpeg:hevc:2015:auxid:2") {
            image->set_is_depth_channel_of(refs[0]);

            auto master_iter = m_all_images.find(refs[0]);
            if (image.get() == master_iter->second.get()) {
              return Error(heif_error_Invalid_input,
                           heif_suberror_Nonexisting_item_referenced,
                           "Recursive depth image detected");
            }
            master_iter->second->set_depth_channel(image);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -576,6 +576,11 @@
             image->set_is_alpha_channel_of(refs[0]);
 
             auto master_iter = m_all_images.find(refs[0]);
+            if (master_iter == m_all_images.end()) {
+              return Error(heif_error_Invalid_input,
+                           heif_suberror_Nonexisting_item_referenced,
+                           "Non-existing alpha image referenced");
+            }
             if (image.get() == master_iter->second.get()) {
               return Error(heif_error_Invalid_input,
                            heif_suberror_Nonexisting_item_referenced,
```
