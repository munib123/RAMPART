# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 3808_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3808_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 132-172 of the vulnerable file.


    :param vg: volume group name
    """
    out, err = execute('vgs', '--noheadings', '--nosuffix',
                       '--units', 'b', '-o', 'vg_free', vg,
                       run_as_root=True)
    return int(out.strip())


def list_logical_volumes(vg):
    """List logical volumes paths for given volume group.

    :param vg: volume group name
    """
    out, err = execute('lvs', '--noheadings', '-o', 'lv_name', vg,
                       run_as_root=True)

    return [line.strip() for line in out.splitlines()]


def remove_logical_volumes(*paths):
    """Remove one or more logical volume."""
    if paths:
        lvremove = ('lvremove', '-f') + paths
        execute(*lvremove, attempts=3, run_as_root=True)


def pick_disk_driver_name(is_block_dev=False):
    """Pick the libvirt primary backend driver name

    If the hypervisor supports multiple backend drivers, then the name
    attribute selects the primary backend driver name, while the optional
    type attribute provides the sub-type.  For example, xen supports a name
    of "tap", "tap2", "phy", or "file", with a type of "aio" or "qcow2",
    while qemu only supports a name of "qemu", but multiple types including
    "raw", "bochs", "qcow2", and "qed".

    :param is_block_dev:
    :returns: driver_name or None
    """
    if FLAGS.libvirt_type == "xen":
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -149,8 +149,52 @@
     return [line.strip() for line in out.splitlines()]
 
 
+def logical_volume_size(path):
+    """Get logical volume size in bytes.
+
+    :param path: logical volume path
+    """
+    # TODO(p-draigbrady) POssibly replace with the more general
+    # use of blockdev --getsize64 in future
+    out, _err = execute('lvs', '-o', 'lv_size', '--noheadings', '--units',
+                        'b', '--nosuffix', path, run_as_root=True)
+
+    return int(out)
+
+
+def clear_logical_volume(path):
+    """Obfuscate the logical volume.
+
+    :param path: logical volume path
+    """
+    # TODO(p-draigbrady): We currently overwrite with zeros
+    # but we may want to make this configurable in future
+    # for more or less security conscious setups.
+
+    vol_size = logical_volume_size(path)
+    bs = 1024 * 1024
+    remaining_bytes = vol_size
+
+    # The loop caters for versions of dd that
+    # don't support the iflag=count_bytes option.
+    while remaining_bytes:
+        zero_blocks = remaining_bytes / bs
+        seek_blocks = (vol_size - remaining_bytes) / bs
+        zero_cmd = ('dd', 'bs=%s' % bs,
+                    'if=/dev/zero', 'of=%s' % path,
+                    'seek=%s' % seek_blocks, 'count=%s' % zero_blocks)
+        if zero_blocks:
+            utils.execute(*zero_cmd, run_as_root=True)
+        remaining_bytes %= bs
+        bs /= 1024  # Limit to 3 iterations
+
+
 def remove_logical_volumes(*paths):
     """Remove one or more logical volume."""
+
+    for path in paths:
+        clear_logical_volume(path)
+
     if paths:
         lvremove = ('lvremove', '-f') + paths
         execute(*lvremove, attempts=3, run_as_root=True)
```
