# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 1706_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1706_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 178-218 of the vulnerable file.


    if (!virtio_queue_ready(port->ovq)) {
        return;
    }
    do_flush_queued_data(port, port->ovq, VIRTIO_DEVICE(port->vser));
}

static size_t send_control_msg(VirtIOSerial *vser, void *buf, size_t len)
{
    VirtQueueElement elem;
    VirtQueue *vq;

    vq = vser->c_ivq;
    if (!virtio_queue_ready(vq)) {
        return 0;
    }
    if (!virtqueue_pop(vq, &elem)) {
        return 0;
    }

    memcpy(elem.in_sg[0].iov_base, buf, len);

    virtqueue_push(vq, &elem, len);
    virtio_notify(VIRTIO_DEVICE(vser), vq);
    return len;
}

static size_t send_control_event(VirtIOSerial *vser, uint32_t port_id,
                                 uint16_t event, uint16_t value)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(vser);
    struct virtio_console_control cpkt;

    virtio_stl_p(vdev, &cpkt.id, port_id);
    virtio_stw_p(vdev, &cpkt.event, event);
    virtio_stw_p(vdev, &cpkt.value, value);

    trace_virtio_serial_send_control_event(port_id, event, value);
    return send_control_msg(vser, &cpkt, sizeof(cpkt));
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -195,7 +195,8 @@
         return 0;
     }
 
-    memcpy(elem.in_sg[0].iov_base, buf, len);
+    /* TODO: detect a buffer that's too short, set NEEDS_RESET */
+    iov_from_buf(elem.in_sg, elem.in_num, 0, buf, len);
 
     virtqueue_push(vq, &elem, len);
     virtio_notify(VIRTIO_DEVICE(vser), vq);
```
