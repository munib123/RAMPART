# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 1183_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1183_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 164-204 of the vulnerable file.

      file_name = 0;
    }
    return file_name;
  }

  unsigned find_file(const Config * config, const char * option, String & filename)
  {
    StringList sl;
    config->retrieve_list(option, &sl);
    return find_file(sl, filename);
  }

  unsigned find_file(const StringList & sl, String & filename)
  {
    StringListEnumeration els = sl.elements_obj();
    const char * dir;
    String path;
    while ( (dir = els.next()) != 0 ) 
    {
      path = dir;
      if (path.back() != '/') path += '/';
      unsigned dir_len = path.size();
      path += filename;
      if (file_exists(path)) {
        filename.swap(path);
        return dir_len;
      }
    }
    return 0;
  }

  PathBrowser::PathBrowser(const StringList & sl, const char * suf)
    : dir_handle(0)
  {
    els = sl.elements();
    suffix = suf;
  }

  PathBrowser::~PathBrowser() 
  {
    delete els;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,6 +181,7 @@
     while ( (dir = els.next()) != 0 ) 
     {
       path = dir;
+      if (path.empty()) continue;
       if (path.back() != '/') path += '/';
       unsigned dir_len = path.size();
       path += filename;
```
