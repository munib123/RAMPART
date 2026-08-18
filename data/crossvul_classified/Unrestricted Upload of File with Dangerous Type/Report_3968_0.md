# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in cpp
**Pair ID:** 3968_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3968_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```cpp
Lines 286-326 of the vulnerable file.

    if (!is_path_safe(filename, trusted))
    {
        lua_pushstring(
            ls,
            make_stringf("invalid filename: %s", filename).c_str());
        return -1;
    }

    string file = datafile_path(filename, die_on_fail);
    if (file.empty())
    {
        lua_pushstring(ls,
                       make_stringf("Can't find \"%s\"", filename).c_str());
        return -1;
    }

    FileLineInput f(file.c_str());
    string script;
    while (!f.eof())
        script += f.get_line() + "\n";

    // prefixing with @ stops lua from adding [string "%s"]
    return luaL_loadbuffer(ls, &script[0], script.length(),
                           ("@" + file).c_str());
}

int CLua::execfile(const char *filename, bool trusted, bool die_on_fail,
                   bool force)
{
    if (!force && sourced_files.count(filename))
        return 0;

    lua_State *ls = state();
    int err = loadfile(ls, filename, trusted || !managed_vm, die_on_fail);
    lua_call_throttle strangler(this);
    if (!err)
        err = lua_pcall(ls, 0, 0, 0);
    if (!err)
        sourced_files.insert(filename);
    set_error(err);
    if (die_on_fail && !error.empty())
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -303,6 +303,9 @@
     string script;
     while (!f.eof())
         script += f.get_line() + "\n";
+
+    if (script[0] == 0x1b)
+        abort();
 
     // prefixing with @ stops lua from adding [string "%s"]
     return luaL_loadbuffer(ls, &script[0], script.length(),
@@ -796,6 +799,8 @@
 
     lua_pushcfunction(_state, lua_loadstring);
     lua_setglobal(_state, "loadstring");
+    lua_pushnil(_state);
+    lua_setglobal(_state, "load");
 
     // Open Crawl bindings
     cluaopen_kills(_state);
```
