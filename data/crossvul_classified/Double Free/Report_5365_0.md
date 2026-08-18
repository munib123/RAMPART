# CrossVul Fix Pair: Double Free in c
**Pair ID:** 5365_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5365_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 976-1016 of the vulnerable file.

* Memory stream object.
\******************************************************************************/

static int mem_read(jas_stream_obj_t *obj, char *buf, int cnt)
{
	int n;
	assert(cnt >= 0);
	assert(buf);
	jas_stream_memobj_t *m = (jas_stream_memobj_t *)obj;
	n = m->len_ - m->pos_;
	cnt = JAS_MIN(n, cnt);
	memcpy(buf, &m->buf_[m->pos_], cnt);
	m->pos_ += cnt;
	return cnt;
}

static int mem_resize(jas_stream_memobj_t *m, int bufsize)
{
	unsigned char *buf;

	assert(m->buf_);
	assert(bufsize >= 0);
	if (!(buf = jas_realloc2(m->buf_, bufsize, sizeof(unsigned char)))) {
		return -1;
	}
	m->buf_ = buf;
	m->bufsize_ = bufsize;
	return 0;
}

static int mem_write(jas_stream_obj_t *obj, char *buf, int cnt)
{
	int n;
	int ret;
	jas_stream_memobj_t *m = (jas_stream_memobj_t *)obj;
	long newbufsize;
	long newpos;

	assert(buf);
	assert(cnt >= 0);
	newpos = m->pos_ + cnt;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -993,9 +993,10 @@
 {
 	unsigned char *buf;
 
-	assert(m->buf_);
+	//assert(m->buf_);
 	assert(bufsize >= 0);
-	if (!(buf = jas_realloc2(m->buf_, bufsize, sizeof(unsigned char)))) {
+	if (!(buf = jas_realloc2(m->buf_, bufsize, sizeof(unsigned char))) &&
+	  bufsize) {
 		return -1;
 	}
 	m->buf_ = buf;
```
