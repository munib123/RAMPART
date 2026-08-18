# CrossVul Fix Pair: 7PK in python
**Pair ID:** 5219_3
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5219_3`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```python
Lines 37-77 of the vulnerable file.


def setup_webdir_if_it_doesnt_exist(ctx):
    if is_web_app(ctx):
        webdirPath = os.path.join(ctx['BUILD_DIR'], ctx['WEBDIR'])
        if not os.path.exists(webdirPath):
            fu = FileUtil(FakeBuilder(ctx), move=True)
            fu.under('BUILD_DIR')
            fu.into('WEBDIR')
            fu.where_name_does_not_match(
                '^%s/.*$' % os.path.join(ctx['BUILD_DIR'], '.bp'))
            fu.where_name_does_not_match(
                '^%s/.*$' % os.path.join(ctx['BUILD_DIR'], '.extensions'))
            fu.where_name_does_not_match(
                '^%s/.*$' % os.path.join(ctx['BUILD_DIR'], '.bp-config'))
            fu.where_name_does_not_match(
                '^%s$' % os.path.join(ctx['BUILD_DIR'], 'manifest.yml'))
            fu.where_name_does_not_match(
                '^%s/.*$' % os.path.join(ctx['BUILD_DIR'], ctx['LIBDIR']))
            fu.where_name_does_not_match(
                '^%s/.*$' % os.path.join(ctx['BUILD_DIR'], '.profile.d'))
            fu.done()


def log_bp_version(ctx):
    version_file = os.path.join(ctx['BP_DIR'], 'VERSION')
    if os.path.exists(version_file):
        print('-------> Buildpack version %s' % open(version_file).read())


def setup_log_dir(ctx):
    os.makedirs(os.path.join(ctx['BUILD_DIR'], 'logs'))


def load_manifest(ctx):
    manifest_path = os.path.join(ctx['BP_DIR'], 'manifest.yml')
    _log.debug('Loading manifest from %s', manifest_path)
    return yaml.load(open(manifest_path))


def find_all_php_versions(dependencies):
    versions = []
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,6 +54,8 @@
                 '^%s/.*$' % os.path.join(ctx['BUILD_DIR'], ctx['LIBDIR']))
             fu.where_name_does_not_match(
                 '^%s/.*$' % os.path.join(ctx['BUILD_DIR'], '.profile.d'))
+            fu.where_name_does_not_match(
+                '^%s$' % os.path.join(ctx['BUILD_DIR'], '.profile'))
             fu.done()
 
 
```
