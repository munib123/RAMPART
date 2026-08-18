# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4734_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4734_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 34-74 of the vulnerable file.

	{ printk(KERN_ERR "magic mismatch: %x (expected %x)\n",is,should); BUG(); }

static int debug = 0;
module_param(debug, int, 0644);

MODULE_DESCRIPTION("helper module to manage video4linux vmalloc buffers");
MODULE_AUTHOR("Mauro Carvalho Chehab <mchehab@infradead.org>");
MODULE_LICENSE("GPL");

#define dprintk(level, fmt, arg...)	if (debug >= level) \
	printk(KERN_DEBUG "vbuf-sg: " fmt , ## arg)


/***************************************************************************/

static void
videobuf_vm_open(struct vm_area_struct *vma)
{
	struct videobuf_mapping *map = vma->vm_private_data;

	dprintk(2,"vm_open %p [count=%d,vma=%08lx-%08lx]\n",map,
		map->count,vma->vm_start,vma->vm_end);

	map->count++;
}

static void
videobuf_vm_close(struct vm_area_struct *vma)
{
	struct videobuf_mapping *map = vma->vm_private_data;
	struct videobuf_queue *q = map->q;
	int i;

	dprintk(2,"vm_close %p [count=%d,vma=%08lx-%08lx]\n",map,
		map->count,vma->vm_start,vma->vm_end);

	map->count--;
	if (0 == map->count) {
		dprintk(1,"munmap %p q=%p\n",map,q);
		mutex_lock(&q->lock);
		for (i = 0; i < VIDEO_MAX_FRAME; i++) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,7 @@
 {
 	struct videobuf_mapping *map = vma->vm_private_data;
 
-	dprintk(2,"vm_open %p [count=%d,vma=%08lx-%08lx]\n",map,
+	dprintk(2,"vm_open %p [count=%u,vma=%08lx-%08lx]\n",map,
 		map->count,vma->vm_start,vma->vm_end);
 
 	map->count++;
@@ -64,7 +64,7 @@
 	struct videobuf_queue *q = map->q;
 	int i;
 
-	dprintk(2,"vm_close %p [count=%d,vma=%08lx-%08lx]\n",map,
+	dprintk(2,"vm_close %p [count=%u,vma=%08lx-%08lx]\n",map,
 		map->count,vma->vm_start,vma->vm_end);
 
 	map->count--;
@@ -221,7 +221,7 @@
 	}
 
 	/* create mapping + update buffer list */
-	map = q->bufs[first]->map = kmalloc(sizeof(struct videobuf_mapping),GFP_KERNEL);
+	map = q->bufs[first]->map = kzalloc(sizeof(struct videobuf_mapping),GFP_KERNEL);
 	if (NULL == map)
 		return -ENOMEM;
 
```
