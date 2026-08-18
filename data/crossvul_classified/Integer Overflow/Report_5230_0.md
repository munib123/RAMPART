# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 5230_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5230_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 107-148 of the vulnerable file.

        ret.append(input.substr(positions[i], positions[i+1]));
      }
    } // else we have negative limit and delimiter not found
  } else {
    ret.append(input);
  }

  return ret;
}

String StringUtil::Implode(const Variant& items, const String& delim,
                           const bool checkIsContainer /* = true */) {
  if (checkIsContainer && !isContainer(items)) {
    throw_param_is_not_container();
  }
  int size = getContainerSize(items);
  if (size == 0) return empty_string();

  req::vector<String> sitems;
  sitems.reserve(size);
  int len = 0;
  int lenDelim = delim.size();
  for (ArrayIter iter(items); iter; ++iter) {
    sitems.emplace_back(iter.second().toString());
    len += sitems.back().size() + lenDelim;
  }
  len -= lenDelim; // always one delimiter less than count of items
  assert(sitems.size() == size);

  String s = String(len, ReserveString);
  char *buffer = s.mutableData();
  const char *sdelim = delim.data();
  char *p = buffer;
  String &init_str = sitems[0];
  int init_len = init_str.size();
  memcpy(p, init_str.data(), init_len);
  p += init_len;
  for (int i = 1; i < size; i++) {
    String &item = sitems[i];
    memcpy(p, sdelim, lenDelim);
    p += lenDelim;
    int lenItem = item.size();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -124,8 +124,8 @@
 
   req::vector<String> sitems;
   sitems.reserve(size);
-  int len = 0;
-  int lenDelim = delim.size();
+  size_t len = 0;
+  size_t lenDelim = delim.size();
   for (ArrayIter iter(items); iter; ++iter) {
     sitems.emplace_back(iter.second().toString());
     len += sitems.back().size() + lenDelim;
```
