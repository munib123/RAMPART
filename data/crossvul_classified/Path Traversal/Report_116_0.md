# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 116_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `116_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 204-245 of the vulnerable file.


    exit_code = 0
    for repo in my.repos.listEnabled():
        reposack = ListPackageSack(my.pkgSack.returnPackages(repoid=repo.id))

        if opts.newest:
            download_list = reposack.returnNewestByNameArch()
        else:
            download_list = list(reposack)

        if opts.norepopath:
            local_repo_path = opts.destdir
        else:
            local_repo_path = opts.destdir + '/' + repo.id

        if opts.delete and os.path.exists(local_repo_path):
            current_pkgs = localpkgs(local_repo_path)

            download_set = {}
            for pkg in download_list:
                remote = pkg.returnSimple('relativepath')
                rpmname = os.path.basename(remote)
                download_set[rpmname] = 1

            for pkg in current_pkgs:
                if pkg in download_set:
                    continue

                if not opts.quiet:
                    my.logger.info("Removing obsolete %s", pkg)
                os.unlink(current_pkgs[pkg]['path'])

        if opts.downloadcomps or opts.downloadmd:

            if not os.path.exists(local_repo_path):
                try:
                    os.makedirs(local_repo_path)
                except IOError, e:
                    my.logger.error("Could not make repo subdir: %s" % e)
                    my.closeRpmDB()
                    sys.exit(1)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -221,8 +221,7 @@
 
             download_set = {}
             for pkg in download_list:
-                remote = pkg.returnSimple('relativepath')
-                rpmname = os.path.basename(remote)
+                rpmname = os.path.basename(pkg.remote_path)
                 download_set[rpmname] = 1
 
             for pkg in current_pkgs:
@@ -269,8 +268,7 @@
         remote_size = 0
         if not opts.urls:
             for pkg in download_list:
-                remote = pkg.returnSimple('relativepath')
-                local = local_repo_path + '/' + remote
+                local = os.path.join(local_repo_path, pkg.remote_path)
                 sz = int(pkg.returnSimple('packagesize'))
                 if os.path.exists(local) and os.path.getsize(local) == sz:
                     continue
@@ -282,10 +280,9 @@
         download_list.sort(key=lambda pkg: pkg.name)
         if opts.urls:
             for pkg in download_list:
-                remote = pkg.returnSimple('relativepath')
-                local = os.path.join(local_repo_path, remote)
+                local = os.path.join(local_repo_path, pkg.remote_path)
                 if not (os.path.exists(local) and my.verifyPkg(local, pkg, False)):
-                    print urljoin(pkg.repo.urls[0], pkg.relativepath)
+                    print urljoin(pkg.repo.urls[0], pkg.remote_path)
             continue
 
         # create dest dir
@@ -294,8 +291,7 @@
 
         # set localpaths
         for pkg in download_list:
-            rpmfn = pkg.remote_path
-            pkg.localpath = os.path.join(local_repo_path, rpmfn)
+            pkg.localpath = os.path.join(local_repo_path, pkg.remote_path)
             pkg.repo.copy_local = True
             pkg.repo.cache = 0
             localdir = os.path.dirname(pkg.localpath)
```
