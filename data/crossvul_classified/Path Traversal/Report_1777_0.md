# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 1777_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1777_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 283-323 of the vulnerable file.

            raise cherrypy.HTTPError(401, 'Unauthorized')
        handler_args = {}
        if 'data' in kwargs:
            handler_args = json.loads(kwargs['data'])
        is_binary = ('binary' in dir(handler) and handler.binary)
        if is_binary:
            return handler(**handler_args)
        else:
            return json.dumps({'data': handler(**handler_args)})

    api.exposed = True

    def download_check_files(self, filelist):
        # only admins and allowed users may download
        if not cherrypy.session['admin']:
            uo = self.useroptions.forUser(self.getUserId())
            if not uo.getOptionValue('media.may_download'):
                return 'not_permitted'
        # make sure nobody tries to escape from basedir
        for f in filelist:
            if '/../' in f:
                return 'invalid_file'
        # make sure all files are smaller than maximum download size
        size_limit = cherry.config['media.maximum_download_size']
        try:
            if self.model.file_size_within_limit(filelist, size_limit):
                return 'ok'
            else:
                return 'too_big'
        except OSError as e:        # use OSError for python2 compatibility
            return str(e)

    def api_downloadcheck(self, filelist):
        status = self.download_check_files(filelist)
        if status == 'not_permitted':
            return """You are not allowed to download files."""
        elif status == 'invalid_file':
            return "Error: invalid filename found in {list}".format(list=filelist)
        elif status == 'too_big':
            size_limit = cherry.config['media.maximum_download_size']
            return """Can't download: Playlist is bigger than {maxsize} mB.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -300,7 +300,11 @@
                 return 'not_permitted'
         # make sure nobody tries to escape from basedir
         for f in filelist:
-            if '/../' in f:
+            # don't allow to traverse up in the file system
+            if '/../' in f or f.startswith('../'):
+                return 'invalid_file'
+            # CVE-2015-8309: do not allow absolute file paths
+            if os.path.isabs(f):
                 return 'invalid_file'
         # make sure all files are smaller than maximum download size
         size_limit = cherry.config['media.maximum_download_size']
```
