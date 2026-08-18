# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 3539_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3539_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 138-178 of the vulnerable file.

        image_uuid = self.get_image_uuid(context, image_id)
        return self.get(self, context, image_uuid)

    @staticmethod
    def _conn(context):
        # NOTE(vish): access and secret keys for s3 server are not
        #             checked in nova-objectstore
        access = FLAGS.s3_access_key
        secret = FLAGS.s3_secret_key
        calling = boto.s3.connection.OrdinaryCallingFormat()
        return boto.s3.connection.S3Connection(aws_access_key_id=access,
                                               aws_secret_access_key=secret,
                                               is_secure=False,
                                               calling_format=calling,
                                               port=FLAGS.s3_port,
                                               host=FLAGS.s3_host)

    @staticmethod
    def _download_file(bucket, filename, local_dir):
        key = bucket.get_key(filename)
        local_filename = os.path.join(local_dir, filename)
        key.get_contents_to_filename(local_filename)
        return local_filename

    def _s3_parse_manifest(self, context, metadata, manifest):
        manifest = ElementTree.fromstring(manifest)
        image_format = 'ami'
        image_type = 'machine'

        try:
            kernel_id = manifest.find('machine_configuration/kernel_id').text
            if kernel_id == 'true':
                image_format = 'aki'
                image_type = 'kernel'
                kernel_id = None
        except Exception:
            kernel_id = None

        try:
            ramdisk_id = manifest.find('machine_configuration/ramdisk_id').text
            if ramdisk_id == 'true':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,7 +155,7 @@
     @staticmethod
     def _download_file(bucket, filename, local_dir):
         key = bucket.get_key(filename)
-        local_filename = os.path.join(local_dir, filename)
+        local_filename = os.path.join(local_dir, os.path.basename(filename))
         key.get_contents_to_filename(local_filename)
         return local_filename
 
@@ -388,7 +388,18 @@
                                      'err': err})
 
     @staticmethod
+    def _test_for_malicious_tarball(path, filename):
+        """Raises exception if extracting tarball would escape extract path"""
+        tar_file = tarfile.open(filename, 'r|gz')
+        for n in tar_file.getnames():
+            if not os.path.abspath(os.path.join(path, n)).startswith(path):
+                tar_file.close()
+                raise exception.Error(_('Unsafe filenames in image'))
+        tar_file.close()
+
+    @staticmethod
     def _untarzip_image(path, filename):
+        S3ImageService._test_for_malicious_tarball(path, filename)
         tar_file = tarfile.open(filename, 'r|gz')
         tar_file.extractall(path)
         image_file = tar_file.getnames()[0]
```
