# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 129_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `129_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 368-408 of the vulnerable file.

    lua_Number n = lua_tonumber(L,-1);

    if (IS_INT64_EQUIVALENT(n)) {
        mp_encode_lua_integer(L, buf);
    } else {
        mp_encode_double(L,buf,(double)n);
    }
}

void mp_encode_lua_type(lua_State *L, mp_buf *buf, int level);

/* Convert a lua table into a message pack list. */
void mp_encode_lua_table_as_array(lua_State *L, mp_buf *buf, int level) {
#if LUA_VERSION_NUM < 502
    size_t len = lua_objlen(L,-1), j;
#else
    size_t len = lua_rawlen(L,-1), j;
#endif

    mp_encode_array(L,buf,len);
    for (j = 1; j <= len; j++) {
        lua_pushnumber(L,j);
        lua_gettable(L,-2);
        mp_encode_lua_type(L,buf,level+1);
    }
}

/* Convert a lua table into a message pack key-value map. */
void mp_encode_lua_table_as_map(lua_State *L, mp_buf *buf, int level) {
    size_t len = 0;

    /* First step: count keys into table. No other way to do it with the
     * Lua API, we need to iterate a first time. Note that an alternative
     * would be to do a single run, and then hack the buffer to insert the
     * map opcodes for message pack. Too hackish for this lib. */
    lua_pushnil(L);
    while(lua_next(L,-2)) {
        lua_pop(L,1); /* remove value, keep key for next iteration. */
        len++;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -385,6 +385,7 @@
 #endif
 
     mp_encode_array(L,buf,len);
+    luaL_checkstack(L, 1, "in function mp_encode_lua_table_as_array");
     for (j = 1; j <= len; j++) {
         lua_pushnumber(L,j);
         lua_gettable(L,-2);
@@ -400,6 +401,7 @@
      * Lua API, we need to iterate a first time. Note that an alternative
      * would be to do a single run, and then hack the buffer to insert the
      * map opcodes for message pack. Too hackish for this lib. */
+    luaL_checkstack(L, 3, "in function mp_encode_lua_table_as_map");
     lua_pushnil(L);
     while(lua_next(L,-2)) {
         lua_pop(L,1); /* remove value, keep key for next iteration. */
@@ -522,6 +524,7 @@
     for(i = 1; i <= nargs; i++) {
         /* Copy argument i to top of stack for _encode processing;
          * the encode function pops it from the stack when complete. */
+        luaL_checkstack(L, 1, "in function mp_check");
         lua_pushvalue(L, i);
 
         mp_encode_lua_type(L,buf,0);
@@ -550,6 +553,7 @@
     int index = 1;
 
     lua_newtable(L);
+    luaL_checkstack(L, 1, "in function mp_decode_to_lua_array");
     while(len--) {
         lua_pushnumber(L,index++);
         mp_decode_to_lua_type(L,c);
@@ -824,6 +828,9 @@
          * subtract the entire buffer size from the unprocessed size
          * to get our next start offset */
         int offset = len - c.left;
+
+        luaL_checkstack(L, 1, "in function mp_unpack_full");
+
         /* Return offset -1 when we have have processed the entire buffer. */
         lua_pushinteger(L, c.left == 0 ? -1 : offset);
         /* Results are returned with the arg elements still
```
