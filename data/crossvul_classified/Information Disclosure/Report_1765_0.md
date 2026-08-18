# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1765_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1765_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 68-108 of the vulnerable file.


	for (y = 0; y < dev->display_height; y++) {
		u16 *d = p;

		for (x = 0; x < dev->display_width; x++)
			d[x] = rgb[(y / 16 + x / 16) % 16];
		p += dev->display_byte_stride;
	}
}

/* --------------------------------------------------------------------- */

static int vivid_fb_ioctl(struct fb_info *info, unsigned cmd, unsigned long arg)
{
	struct vivid_dev *dev = (struct vivid_dev *)info->par;

	switch (cmd) {
	case FBIOGET_VBLANK: {
		struct fb_vblank vblank;

		vblank.flags = FB_VBLANK_HAVE_COUNT | FB_VBLANK_HAVE_VCOUNT |
			FB_VBLANK_HAVE_VSYNC;
		vblank.count = 0;
		vblank.vcount = 0;
		vblank.hcount = 0;
		if (copy_to_user((void __user *)arg, &vblank, sizeof(vblank)))
			return -EFAULT;
		return 0;
	}

	default:
		dprintk(dev, 1, "Unknown ioctl %08x\n", cmd);
		return -EINVAL;
	}
	return 0;
}

/* Framebuffer device handling */

static int vivid_fb_set_var(struct vivid_dev *dev, struct fb_var_screeninfo *var)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,6 +85,7 @@
 	case FBIOGET_VBLANK: {
 		struct fb_vblank vblank;
 
+		memset(&vblank, 0, sizeof(vblank));
 		vblank.flags = FB_VBLANK_HAVE_COUNT | FB_VBLANK_HAVE_VCOUNT |
 			FB_VBLANK_HAVE_VSYNC;
 		vblank.count = 0;
```
