# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 5228_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5228_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 537-577 of the vulnerable file.

  mbfl_encoding **entry, **list;

  list = nullptr;
  if (value == nullptr || value_length <= 0) {
    if (return_list) {
      *return_list = nullptr;
    }
    if (return_size) {
      *return_size = 0;
    }
    return 0;
  } else {
    mbfl_no_encoding *identify_list;
    int identify_list_size;

    identify_list = MBSTRG(default_detect_order_list);
    identify_list_size = MBSTRG(default_detect_order_list_size);

    /* copy the value string for work */
    if (value[0]=='"' && value[value_length-1]=='"' && value_length>2) {
      tmpstr = (char *)strndup(value+1, value_length-2);
      value_length -= 2;
    }
    else
      tmpstr = (char *)strndup(value, value_length);
    if (tmpstr == nullptr) {
      return 0;
    }
    /* count the number of listed encoding names */
    endp = tmpstr + value_length;
    n = 1;
    p1 = tmpstr;
    while ((p2 = (char*)string_memnstr(p1, ",", 1, endp)) != nullptr) {
      p1 = p2 + 1;
      n++;
    }
    size = n + identify_list_size;
    /* make list */
    list = (mbfl_encoding **)calloc(size, sizeof(mbfl_encoding*));
    if (list != nullptr) {
      entry = list;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -554,11 +554,11 @@
 
     /* copy the value string for work */
     if (value[0]=='"' && value[value_length-1]=='"' && value_length>2) {
-      tmpstr = (char *)strndup(value+1, value_length-2);
+      tmpstr = req::strndup(value + 1, value_length - 2);
       value_length -= 2;
-    }
-    else
-      tmpstr = (char *)strndup(value, value_length);
+    } else {
+      tmpstr = req::strndup(value, value_length);
+    }
     if (tmpstr == nullptr) {
       return 0;
     }
@@ -640,7 +640,7 @@
       }
       ret = 0;
     }
-    free(tmpstr);
+    req::free(tmpstr);
   }
 
   return ret;
@@ -2254,11 +2254,11 @@
   info.num_from_encodings     = MBSTRG(http_input_list_size);
   info.from_language          = MBSTRG(current_language);
 
-  char *encstr = strndup(encoded_string.data(), encoded_string.size());
+  char *encstr = req::strndup(encoded_string.data(), encoded_string.size());
   Array resultArr = Array::Create();
   mbfl_encoding *detected =
     _php_mb_encoding_handler_ex(&info, resultArr, encstr);
-  free(encstr);
+  req::free(encstr);
   result.assignIfRef(resultArr);
 
   MBSTRG(http_input_identify) = detected;
@@ -4251,7 +4251,7 @@
   if (!to.empty()) {
     int to_len = to.size();
     if (to_len > 0) {
-      to_r = strndup(to.data(), to_len);
+      to_r = req::strndup(to.data(), to_len);
       for (; to_len; to_len--) {
         if (!isspace((unsigned char)to_r[to_len - 1])) {
           break;
@@ -4398,6 +4398,9 @@
                                encoded_message.data(),
                                all_headers, cmd.data()));
   mbfl_memory_device_clear(&device);
+  if (to_r != to.data()) {
+    req::free(to_r);
+  }
   return ret;
 }
 
```
