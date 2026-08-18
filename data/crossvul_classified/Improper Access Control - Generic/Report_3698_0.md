# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3698_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3698_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 172-198 of the vulnerable file.

    # nova/network/linux_net.py: 'radvd', '-C', '%s' % _ra_file(dev, 'conf'),..
    filters.CommandFilter("/usr/sbin/radvd", "root"),

    # nova/network/linux_net.py: 'brctl', 'addbr', bridge
    # nova/network/linux_net.py: 'brctl', 'setfd', bridge, 0
    # nova/network/linux_net.py: 'brctl', 'stp', bridge, 'off'
    # nova/network/linux_net.py: 'brctl', 'addif', bridge, interface
    filters.CommandFilter("/sbin/brctl", "root"),
    filters.CommandFilter("/usr/sbin/brctl", "root"),

    # nova/virt/libvirt/utils.py: 'mkswap'
    # nova/virt/xenapi/vm_utils.py: 'mkswap'
    filters.CommandFilter("/sbin/mkswap", "root"),

    # nova/virt/xenapi/vm_utils.py: 'mkfs'
    filters.CommandFilter("/sbin/mkfs", "root"),

    # nova/virt/libvirt/utils.py: 'qemu-img'
    filters.CommandFilter("/usr/bin/qemu-img", "root"),

    # nova/virt/disk/api.py: 'touch', target
    filters.CommandFilter("/usr/bin/touch", "root"),

    # nova/virt/libvirt/connection.py:
    filters.ReadFileFilter("/etc/iscsi/initiatorname.iscsi"),

    ]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -189,6 +189,10 @@
     # nova/virt/libvirt/utils.py: 'qemu-img'
     filters.CommandFilter("/usr/bin/qemu-img", "root"),
 
+    # nova/virt/disk/api.py: 'readlink', '-e'
+    filters.CommandFilter("/usr/bin/readlink", "root"),
+    filters.CommandFilter("/bin/readlink", "root"),
+
     # nova/virt/disk/api.py: 'touch', target
     filters.CommandFilter("/usr/bin/touch", "root"),
 
```
