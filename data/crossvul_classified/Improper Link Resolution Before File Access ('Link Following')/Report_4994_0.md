# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in python
**Pair ID:** 4994_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4994_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```python
Lines 127-167 of the vulnerable file.

        choices:
          - true
          - false
        description:
          - Create a snapshot a container when cloning. This is not supported
            by all container storage backends. Enabling this may fail if the
            backing store does not support snapshots.
        default: false
    archive:
        choices:
          - true
          - false
        description:
          - Create an archive of a container. This will create a tarball of the
            running container.
        default: false
    archive_path:
        description:
          - Path the save the archived container. If the path does not exist
            the archive method will attempt to create it.
        default: /tmp
    archive_compression:
        choices:
          - gzip
          - bzip2
          - none
        description:
          - Type of compression to use when creating an archive of a running
            container.
        default: gzip
    state:
        choices:
          - started
          - stopped
          - restarted
          - absent
          - frozen
        description:
          - Define the state of a container. If you clone a container using
            `clone_name` the newly cloned container created in a stopped state.
            The running container will be stopped while the clone operation is
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,7 +144,7 @@
         description:
           - Path the save the archived container. If the path does not exist
             the archive method will attempt to create it.
-        default: /tmp
+        default: null
     archive_compression:
         choices:
           - gzip
@@ -557,13 +557,8 @@
     import subprocess
     import tempfile
 
-    # Ensure that the directory /opt exists.
-    if not path.isdir('/opt'):
-        os.mkdir('/opt')
-
-    # Create the script.
-    script_file = path.join('/opt', '.lxc-attach-script')
-    f = open(script_file, 'wb')
+    (fd, script_file) = tempfile.mkstemp(prefix='lxc-attach-script')
+    f = os.fdopen(fd, 'wb')
     try:
         f.write(ATTACH_TEMPLATE % {'container_command': command})
         f.flush()
@@ -573,14 +568,11 @@
     # Ensure the script is executable.
     os.chmod(script_file, 0700)
 
-    # Get temporary directory.
-    tempdir = tempfile.gettempdir()
-
     # Output log file.
-    stdout_file = open(path.join(tempdir, 'lxc-attach-script.log'), 'ab')
+    stdout_file = os.fdopen(tempfile.mkstemp(prefix='lxc-attach-script-log')[0], 'ab')
 
     # Error log file.
-    stderr_file = open(path.join(tempdir, 'lxc-attach-script.err'), 'ab')
+    stderr_file = os.fdopen(tempfile.mkstemp(prefix='lxc-attach-script-err')[0], 'ab')
 
     # Execute the script command.
     try:
@@ -1747,7 +1739,6 @@
             ),
             archive_path=dict(
                 type='str',
-                default='/tmp'
             ),
             archive_compression=dict(
                 choices=LXC_COMPRESSION_MAP.keys(),
@@ -1755,6 +1746,9 @@
             )
         ),
         supports_check_mode=False,
+        required_if = ([
+            ('archive', True, ['archive_path'])
+        ]),
     )
 
     if not HAS_LXC:
```
