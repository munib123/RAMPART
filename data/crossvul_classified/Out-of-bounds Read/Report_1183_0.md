# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 1183_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1183_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 746-786 of the vulnerable file.

        out.add(b);
      }
      ++s;
    }
  }

  void combine_list(String & res, const StringList & in)
  {
    res.clear();
    StringListEnumeration els = in.elements_obj();
    const char * s = 0;
    while ( (s = els.next()) != 0) 
    {
      for (; *s; ++s) {
        if (*s == ':')
          res.append('\\');
        res.append(*s);
      }
      res.append(':');
    }
    if (res.back() == ':') res.pop_back();
  }

  struct ListAddHelper : public AddableContainer 
  {
    Config * config;
    Config::Entry * orig_entry;
    PosibErr<bool> add(ParmStr val);
  };

  PosibErr<bool> ListAddHelper::add(ParmStr val)
  {
    Config::Entry * entry = new Config::Entry(*orig_entry);
    entry->value = val;
    entry->action = Config::ListAdd;
    config->set(entry);
    return true;
  }

  void Config::replace_internal(ParmStr key, ParmStr value)
  {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -763,7 +763,7 @@
       }
       res.append(':');
     }
-    if (res.back() == ':') res.pop_back();
+    if (!res.empty() && res.back() == ':') res.pop_back();
   }
 
   struct ListAddHelper : public AddableContainer 
```
