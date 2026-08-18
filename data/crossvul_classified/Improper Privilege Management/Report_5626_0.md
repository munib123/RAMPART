# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 5626_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5626_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 551-591 of the vulnerable file.

    virtio_notify_vector(vdev, vdev->config_vector);

    for(i = 0; i < VIRTIO_PCI_QUEUE_MAX; i++) {
        vdev->vq[i].vring.desc = 0;
        vdev->vq[i].vring.avail = 0;
        vdev->vq[i].vring.used = 0;
        vdev->vq[i].last_avail_idx = 0;
        vdev->vq[i].pa = 0;
        vdev->vq[i].vector = VIRTIO_NO_VECTOR;
        vdev->vq[i].signalled_used = 0;
        vdev->vq[i].signalled_used_valid = false;
        vdev->vq[i].notification = true;
    }
}

uint32_t virtio_config_readb(VirtIODevice *vdev, uint32_t addr)
{
    VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
    uint8_t val;

    k->get_config(vdev, vdev->config);

    if (addr > (vdev->config_len - sizeof(val)))
        return (uint32_t)-1;

    val = ldub_p(vdev->config + addr);
    return val;
}

uint32_t virtio_config_readw(VirtIODevice *vdev, uint32_t addr)
{
    VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
    uint16_t val;

    k->get_config(vdev, vdev->config);

    if (addr > (vdev->config_len - sizeof(val)))
        return (uint32_t)-1;

    val = lduw_p(vdev->config + addr);
    return val;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -568,10 +568,11 @@
     VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
     uint8_t val;
 
+    if (addr + sizeof(val) > vdev->config_len) {
+        return (uint32_t)-1;
+    }
+
     k->get_config(vdev, vdev->config);
-
-    if (addr > (vdev->config_len - sizeof(val)))
-        return (uint32_t)-1;
 
     val = ldub_p(vdev->config + addr);
     return val;
@@ -582,10 +583,11 @@
     VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
     uint16_t val;
 
+    if (addr + sizeof(val) > vdev->config_len) {
+        return (uint32_t)-1;
+    }
+
     k->get_config(vdev, vdev->config);
-
-    if (addr > (vdev->config_len - sizeof(val)))
-        return (uint32_t)-1;
 
     val = lduw_p(vdev->config + addr);
     return val;
@@ -596,10 +598,11 @@
     VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
     uint32_t val;
 
+    if (addr + sizeof(val) > vdev->config_len) {
+        return (uint32_t)-1;
+    }
+
     k->get_config(vdev, vdev->config);
-
-    if (addr > (vdev->config_len - sizeof(val)))
-        return (uint32_t)-1;
 
     val = ldl_p(vdev->config + addr);
     return val;
@@ -610,8 +613,9 @@
     VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
     uint8_t val = data;
 
-    if (addr > (vdev->config_len - sizeof(val)))
+    if (addr + sizeof(val) > vdev->config_len) {
         return;
+    }
 
     stb_p(vdev->config + addr, val);
 
@@ -625,8 +629,9 @@
     VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
     uint16_t val = data;
 
-    if (addr > (vdev->config_len - sizeof(val)))
+    if (addr + sizeof(val) > vdev->config_len) {
         return;
+    }
 
     stw_p(vdev->config + addr, val);
 
@@ -640,8 +645,9 @@
     VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
     uint32_t val = data;
 
-    if (addr > (vdev->config_len - sizeof(val)))
+    if (addr + sizeof(val) > vdev->config_len) {
         return;
+    }
 
     stl_p(vdev->config + addr, val);
 
```
