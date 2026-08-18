# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 115_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `115_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 57-97 of the vulnerable file.

        self.opts = opts

def localpkgs(directory):
    names = os.listdir(directory)

    cache = {}
    for name in names:
        fn = os.path.join(directory, name)
        try:
            st = os.lstat(fn)
        except os.error:
            continue
        if stat.S_ISDIR(st.st_mode):
            subcache = localpkgs(fn)
            for pkg in subcache.keys():
                cache[pkg] = subcache[pkg]
        elif stat.S_ISREG(st.st_mode) and name.endswith(".rpm"):
            cache[name] = {'path': fn, 'size': st.st_size, 'device': st.st_dev}
    return cache

def parseArgs():
    usage = _("""
    Reposync is used to synchronize a remote yum repository to a local 
    directory using yum to retrieve the packages.
    
    %s [options]
    """) % sys.argv[0]

    parser = OptionParser(usage=usage)
    parser.add_option("-c", "--config", default='/etc/yum.conf',
        help=_('config file to use (defaults to /etc/yum.conf)'))
    parser.add_option("-a", "--arch", default=None,
        help=_('act as if running the specified arch (default: current arch, note: does not override $releasever. x86_64 is a superset for i*86.)'))
    parser.add_option("--source", default=False, dest="source", action="store_true",
                      help=_('operate on source packages'))
    parser.add_option("-r", "--repoid", default=[], action='append',
        help=_("specify repo ids to query, can be specified multiple times (default is all enabled)"))
    parser.add_option("-e", "--cachedir",
        help=_("directory in which to store metadata"))
    parser.add_option("-t", "--tempcache", default=False, action="store_true",
        help=_("Use a temp dir for storing/accessing yum-cache"))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,6 +73,12 @@
         elif stat.S_ISREG(st.st_mode) and name.endswith(".rpm"):
             cache[name] = {'path': fn, 'size': st.st_size, 'device': st.st_dev}
     return cache
+
+def is_subpath(path, root):
+    root = os.path.realpath(root)
+    path = os.path.realpath(os.path.join(root, path))
+    # join() is used below to ensure root ends with a slash
+    return path.startswith(os.path.join(root, ''))
 
 def parseArgs():
     usage = _("""
@@ -116,6 +122,10 @@
     parser.add_option("", "--download-metadata", dest="downloadmd",
         default=False, action="store_true",
         help=_("download all the non-default metadata"))
+    parser.add_option("", "--allow-path-traversal", default=False,
+        action="store_true",
+        help=_("Allow packages stored outside their repo directory to be synced "
+               "(UNSAFE, USE WITH CAUTION!)"))
     (opts, args) = parser.parse_args()
     return (opts, args)
 
@@ -215,6 +225,30 @@
             local_repo_path = opts.destdir
         else:
             local_repo_path = opts.destdir + '/' + repo.id
+
+        # Ensure we don't traverse out of local_repo_path by dropping any
+        # packages whose remote_path is absolute or contains up-level
+        # references (unless explicitly allowed).
+        # See RHBZ#1600221 for details.
+        if not opts.allow_path_traversal:
+            newlist = []
+            skipped = False
+            for pkg in download_list:
+                if is_subpath(pkg.remote_path, local_repo_path):
+                    newlist.append(pkg)
+                    continue
+                my.logger.warning(
+                    _('WARNING: skipping package %s: remote path "%s" not '
+                      'within repodir, unsafe to mirror locally')
+                    % (pkg, pkg.remote_path)
+                )
+                skipped = True
+            if skipped:
+                my.logger.info(
+                    _('You can enable unsafe remote paths by using '
+                      '--allow-path-traversal (see reposync(1) for details)')
+                )
+            download_list = newlist
 
         if opts.delete and os.path.exists(local_repo_path):
             current_pkgs = localpkgs(local_repo_path)
```
