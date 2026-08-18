# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5120_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5120_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1055-1095 of the vulnerable file.

			V4L2_CID_RF_TUNER_MIXER_GAIN, 0, 15, 1, 8);
	v4l2_ctrl_auto_cluster(2, &s->mixer_gain_auto, 0, false);
	s->if_gain = v4l2_ctrl_new_std(&s->hdl, &airspy_ctrl_ops,
			V4L2_CID_RF_TUNER_IF_GAIN, 0, 15, 1, 0);
	if (s->hdl.error) {
		ret = s->hdl.error;
		dev_err(s->dev, "Could not initialize controls\n");
		goto err_free_controls;
	}

	v4l2_ctrl_handler_setup(&s->hdl);

	s->v4l2_dev.ctrl_handler = &s->hdl;
	s->vdev.v4l2_dev = &s->v4l2_dev;
	s->vdev.lock = &s->v4l2_lock;

	ret = video_register_device(&s->vdev, VFL_TYPE_SDR, -1);
	if (ret) {
		dev_err(s->dev, "Failed to register as video device (%d)\n",
				ret);
		goto err_unregister_v4l2_dev;
	}
	dev_info(s->dev, "Registered as %s\n",
			video_device_node_name(&s->vdev));
	dev_notice(s->dev, "SDR API is still slightly experimental and functionality changes may follow\n");
	return 0;

err_free_controls:
	v4l2_ctrl_handler_free(&s->hdl);
err_unregister_v4l2_dev:
	v4l2_device_unregister(&s->v4l2_dev);
err_free_mem:
	kfree(s);
	return ret;
}

/* USB device ID list */
static struct usb_device_id airspy_id_table[] = {
	{ USB_DEVICE(0x1d50, 0x60a1) }, /* AirSpy */
	{ }
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1072,7 +1072,7 @@
 	if (ret) {
 		dev_err(s->dev, "Failed to register as video device (%d)\n",
 				ret);
-		goto err_unregister_v4l2_dev;
+		goto err_free_controls;
 	}
 	dev_info(s->dev, "Registered as %s\n",
 			video_device_node_name(&s->vdev));
@@ -1081,7 +1081,6 @@
 
 err_free_controls:
 	v4l2_ctrl_handler_free(&s->hdl);
-err_unregister_v4l2_dev:
 	v4l2_device_unregister(&s->v4l2_dev);
 err_free_mem:
 	kfree(s);
```
