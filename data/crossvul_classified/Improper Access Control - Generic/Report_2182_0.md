# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2182_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2182_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 80-125 of the vulnerable file.

  if (fd < 0)
    {
      perror ("socket");
      return -1;
    }

  path = create_socket_name ("fep-XXXXXX/control");
  if (strlen (path) + 1 >= sizeof(sun.sun_path))
    {
      fep_log (FEP_LOG_LEVEL_WARNING,
	       "unix domain socket path too long: %d + 1 >= %d",
	       strlen (path),
	       sizeof (sun.sun_path));
      free (path);
      return -1;
    }

  memset (&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;

#ifdef __linux__
  sun.sun_path[0] = '\0';
  memcpy (sun.sun_path + 1, path, strlen (path));
  sun_len = offsetof (struct sockaddr_un, sun_path) + strlen (path) + 1;
  remove_control_socket (path);
#else
  memcpy (sun.sun_path, path, strlen (path));
  sun_len = sizeof (struct sockaddr_un);
#endif

  if (bind (fd, (const struct sockaddr *) &sun, sun_len) < 0)
    {
      perror ("bind");
      free (path);
      close (fd);
      return -1;
    }

  if (listen (fd, 5) < 0)
    {
      perror ("listen");
      free (path);
      close (fd);
      return -1;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,15 +97,8 @@
   memset (&sun, 0, sizeof(sun));
   sun.sun_family = AF_UNIX;
 
-#ifdef __linux__
-  sun.sun_path[0] = '\0';
-  memcpy (sun.sun_path + 1, path, strlen (path));
-  sun_len = offsetof (struct sockaddr_un, sun_path) + strlen (path) + 1;
-  remove_control_socket (path);
-#else
   memcpy (sun.sun_path, path, strlen (path));
   sun_len = sizeof (struct sockaddr_un);
-#endif
 
   if (bind (fd, (const struct sockaddr *) &sun, sun_len) < 0)
     {
```
