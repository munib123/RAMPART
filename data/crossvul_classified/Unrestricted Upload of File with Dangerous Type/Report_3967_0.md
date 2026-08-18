# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in cpp
**Pair ID:** 3967_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3967_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```cpp
Lines 759-799 of the vulnerable file.

        {LUA_TABLIBNAME, luaopen_table},
        {LUA_STRLIBNAME, luaopen_string},
        {LUA_MATHLIBNAME, luaopen_math},
    };

    for (auto l : lua_core_libs)
    {
        lua_pushcfunction(_state, l.second);
        lua_pushstring(_state, l.first.c_str());
        lua_call(_state, 1, 0);
    }
#endif

    lua_pushboolean(_state, managed_vm);
    setregistry("lua_vm_is_managed");

    lua_pushlightuserdata(_state, this);
    setregistry("__clua");
}

void CLua::init_libraries()
{
    lua_stack_cleaner clean(state());

    // Open Crawl bindings
    cluaopen_kills(_state);
    cluaopen_you(_state);
    cluaopen_item(_state);
    cluaopen_food(_state);
    cluaopen_crawl(_state);
    cluaopen_file(_state);
    cluaopen_moninf(_state);
    cluaopen_options(_state);
    cluaopen_travel(_state);
    cluaopen_view(_state);
    cluaopen_spells(_state);

    cluaopen_globals(_state);

    execfile("dlua/macro.lua", true, true);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -776,9 +776,26 @@
     setregistry("__clua");
 }
 
+static int lua_loadstring(lua_State *ls)
+{
+    const auto lua = luaL_checkstring(ls, 1);
+    if (lua[0] == 0x1b)
+        abort();
+    lua_settop(ls, 0);
+    if (luaL_loadstring(ls, lua))
+    {
+        lua_pushnil(ls);
+        lua_insert(ls, 1);
+    }
+    return lua_gettop(ls);
+}
+
 void CLua::init_libraries()
 {
     lua_stack_cleaner clean(state());
+
+    lua_pushcfunction(_state, lua_loadstring);
+    lua_setglobal(_state, "loadstring");
 
     // Open Crawl bindings
     cluaopen_kills(_state);
```
