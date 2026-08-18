# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4681_1
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4681_1`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 207-248 of the vulnerable file.

                strcat (new_modes, str_mode);
            }
            else
            {
                ptr_arg = NULL;
                switch (irc_mode_get_chanmode_type (server, pos[0]))
                {
                    case 'A': /* always argument */
                    case 'B': /* always argument */
                    case 'C': /* argument if set */
                        ptr_arg = (current_arg < argc) ?
                            argv[current_arg] : NULL;
                        break;
                    case 'D': /* no argument */
                        break;
                }
                if (ptr_arg)
                    current_arg++;
                if (pos[0] == chanmode)
                {
                    chanmode_found = 1;
                    if (set_flag == '+')
                    {
                        str_mode[0] = pos[0];
                        str_mode[1] = '\0';
                        strcat (new_modes, str_mode);
                        if (argument)
                        {
                            if (new_args[0])
                                strcat (new_args, " ");
                            strcat (new_args, argument);
                        }
                    }
                }
                else
                {
                    str_mode[0] = pos[0];
                    str_mode[1] = '\0';
                    strcat (new_modes, str_mode);
                    if (ptr_arg)
                    {
                        if (new_args[0])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,17 +224,20 @@
                     current_arg++;
                 if (pos[0] == chanmode)
                 {
-                    chanmode_found = 1;
-                    if (set_flag == '+')
+                    if (!chanmode_found)
                     {
-                        str_mode[0] = pos[0];
-                        str_mode[1] = '\0';
-                        strcat (new_modes, str_mode);
-                        if (argument)
+                        chanmode_found = 1;
+                        if (set_flag == '+')
                         {
-                            if (new_args[0])
-                                strcat (new_args, " ");
-                            strcat (new_args, argument);
+                            str_mode[0] = pos[0];
+                            str_mode[1] = '\0';
+                            strcat (new_modes, str_mode);
+                            if (argument)
+                            {
+                                if (new_args[0])
+                                    strcat (new_args, " ");
+                                strcat (new_args, argument);
+                            }
                         }
                     }
                 }
```
