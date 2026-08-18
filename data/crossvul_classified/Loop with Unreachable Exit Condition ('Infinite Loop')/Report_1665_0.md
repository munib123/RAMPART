# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 1665_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1665_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 2148-2188 of the vulnerable file.

        if (len == 1)
            return 10;

        framebuffer_update_request(vs,
                                   read_u8(data, 1), read_u16(data, 2), read_u16(data, 4),
                                   read_u16(data, 6), read_u16(data, 8));
        break;
    case VNC_MSG_CLIENT_KEY_EVENT:
        if (len == 1)
            return 8;

        key_event(vs, read_u8(data, 1), read_u32(data, 4));
        break;
    case VNC_MSG_CLIENT_POINTER_EVENT:
        if (len == 1)
            return 6;

        pointer_event(vs, read_u8(data, 1), read_u16(data, 2), read_u16(data, 4));
        break;
    case VNC_MSG_CLIENT_CUT_TEXT:
        if (len == 1)
            return 8;

        if (len == 8) {
            uint32_t dlen = read_u32(data, 4);
            if (dlen > 0)
                return 8 + dlen;
        }

        client_cut_text(vs, read_u32(data, 4), data + 8);
        break;
    case VNC_MSG_CLIENT_QEMU:
        if (len == 1)
            return 2;

        switch (read_u8(data, 1)) {
        case VNC_MSG_CLIENT_QEMU_EXT_KEY_EVENT:
            if (len == 2)
                return 12;

            ext_key_event(vs, read_u16(data, 2),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2165,13 +2165,20 @@
         pointer_event(vs, read_u8(data, 1), read_u16(data, 2), read_u16(data, 4));
         break;
     case VNC_MSG_CLIENT_CUT_TEXT:
-        if (len == 1)
+        if (len == 1) {
             return 8;
-
+        }
         if (len == 8) {
             uint32_t dlen = read_u32(data, 4);
-            if (dlen > 0)
+            if (dlen > (1 << 20)) {
+                error_report("vnc: client_cut_text msg payload has %u bytes"
+                             " which exceeds our limit of 1MB.", dlen);
+                vnc_client_error(vs);
+                break;
+            }
+            if (dlen > 0) {
                 return 8 + dlen;
+            }
         }
 
         client_cut_text(vs, read_u32(data, 4), data + 8);
```
