# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4094_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4094_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 290-330 of the vulnerable file.

    # FIXME: Don't override 'default_value' ("") or 'allow_none' (False) (Breaking change)
    service_account = Unicode(
        None,
        allow_none=True,
        config=True,
        help="""
        The service account to be mounted in the spawned user pod.

        When set to `None` (the default), no service account is mounted, and the default service account
        is explicitly disabled.

        This `serviceaccount` must already exist in the namespace the user pod is being spawned in.

        WARNING: Be careful with this configuration! Make sure the service account being mounted
        has the minimal permissions needed, and nothing more. When misconfigured, this can easily
        give arbitrary users root over your entire cluster.
        """
    )

    pod_name_template = Unicode(
        'jupyter-{username}{servername}',
        config=True,
        help="""
        Template to use to form the name of user's pods.

        `{username}` is expanded to the escaped, dns-label safe username.

        This must be unique within the namespace the pods are being spawned
        in, so if you are running multiple jupyterhubs spawning in the
        same namespace, consider setting this to be something more unique.
        """
    )

    storage_pvc_ensure = Bool(
        False,
        config=True,
        help="""
        Ensure that a PVC exists for each user before spawning.

        Set to true to create a PVC named with `pvc_name_template` if it does
        not exist for the user when their pod is spawning.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -307,16 +307,25 @@
     )
 
     pod_name_template = Unicode(
-        'jupyter-{username}{servername}',
+        'jupyter-{username}--{servername}',
         config=True,
         help="""
         Template to use to form the name of user's pods.
 
-        `{username}` is expanded to the escaped, dns-label safe username.
+        `{username}` is expanded to the escaped, dns-label-safe username.
+        `{servername}` is expanded to the escaped, dns-label-safe server name, if any.
+
+        Trailing `-` characters are stripped for safe handling of empty server names (user default servers).
 
         This must be unique within the namespace the pods are being spawned
         in, so if you are running multiple jupyterhubs spawning in the
         same namespace, consider setting this to be something more unique.
+
+        .. versionchanged:: 0.12
+            `--` delimiter added to the template,
+            where it was implicitly added to the `servername` field before.
+            Additionally, `username--servername` delimiter was `-` instead of `--`,
+            allowing collisions in certain circumstances.
         """
     )
 
@@ -332,16 +341,25 @@
     )
 
     pvc_name_template = Unicode(
-        'claim-{username}{servername}',
+        'claim-{username}--{servername}',
         config=True,
         help="""
         Template to use to form the name of user's pvc.
 
         `{username}` is expanded to the escaped, dns-label safe username.
+        `{servername}` is expanded to the escaped, dns-label-safe server name, if any.
+
+        Trailing `-` characters are stripped for safe handling of empty server names (user default servers).
 
         This must be unique within the namespace the pvc are being spawned
         in, so if you are running multiple jupyterhubs spawning in the
         same namespace, consider setting this to be something more unique.
+
+        .. versionchanged:: 0.12
+            `--` delimiter added to the template,
+            where it was implicitly added to the `servername` field before.
+            Additionally, `username--servername` delimiter was `-` instead of `--`,
+            allowing collisions in certain circumstances.
         """
     )
 
@@ -1313,28 +1331,22 @@
         # Note: '-' is not in safe_chars, as it is being used as escape character
         safe_chars = set(string.ascii_lowercase + string.digits)
 
-        # Set servername based on whether named-server initialised
-        if self.name:
-            # use two -- to ensure no collision possibilities
-            # are created by an ambiguous boundary between username and
-            # servername.
-            # -- cannot occur in a string where - is the escape char.
-            servername = '--{}'.format(self.name)
-            safe_servername = '--{}'.format(escapism.escape(self.name, safe=safe_chars, escape_char='-').lower())
-        else:
-            servername = ''
-            safe_servername = ''
+        raw_servername = self.name or ''
+        safe_servername = escapism.escape(raw_servername, safe=safe_chars, escape_char='-').lower()
 
         legacy_escaped_username = ''.join([s if s in safe_chars else '-' for s in self.user.name.lower()])
         safe_username = escapism.escape(self.user.name, safe=safe_chars, escape_char='-').lower()
-        return template.format(
+        rendered = template.format(
             userid=self.user.id,
             username=safe_username,
             unescaped_username=self.user.name,
             legacy_escape_username=legacy_escaped_username,
             servername=safe_servername,
-            unescaped_servername=servername,
+            unescaped_servername=raw_servername,
         )
+        # strip trailing - delimiter in case of empty servername.
+        # k8s object names cannot have trailing -
+        return rendered.rstrip("-")
 
     def _expand_all(self, src):
         if isinstance(src, list):
```
