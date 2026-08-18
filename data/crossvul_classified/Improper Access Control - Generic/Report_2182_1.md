# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2182_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2182_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 73-117 of the vulnerable file.

  if (!address)
    return NULL;

  if (strlen (address) + 1 >= sizeof(sun.sun_path))
    {
      fep_log (FEP_LOG_LEVEL_WARNING,
	       "unix domain socket path too long: %d + 1 >= %d",
	       strlen (address),
	       sizeof (sun.sun_path));
      free (address);
      return NULL;
    }

  client = xzalloc (sizeof(FepClient));
  client->filter_running = false;
  client->messages = NULL;

  memset (&sun, 0, sizeof(struct sockaddr_un));
  sun.sun_family = AF_UNIX;

#ifdef __linux__
  sun.sun_path[0] = '\0';
  memcpy (sun.sun_path + 1, address, strlen (address));
  sun_len = offsetof (struct sockaddr_un, sun_path) + strlen (address) + 1;
#else
  memcpy (sun.sun_path, address, strlen (address));
  sun_len = sizeof (struct sockaddr_un);
#endif

  client->control = socket (AF_UNIX, SOCK_STREAM, 0);
  if (client->control < 0)
    {
      free (client);
      return NULL;
    }

  retval = connect (client->control,
		    (const struct sockaddr *) &sun,
		    sun_len);
  if (retval < 0)
    {
      close (client->control);
      free (client);
      return NULL;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,14 +90,8 @@
   memset (&sun, 0, sizeof(struct sockaddr_un));
   sun.sun_family = AF_UNIX;
 
-#ifdef __linux__
-  sun.sun_path[0] = '\0';
-  memcpy (sun.sun_path + 1, address, strlen (address));
-  sun_len = offsetof (struct sockaddr_un, sun_path) + strlen (address) + 1;
-#else
   memcpy (sun.sun_path, address, strlen (address));
   sun_len = sizeof (struct sockaddr_un);
-#endif
 
   client->control = socket (AF_UNIX, SOCK_STREAM, 0);
   if (client->control < 0)
```
