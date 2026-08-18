# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1499_1
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1499_1`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 51-91 of the vulnerable file.

		.iov_len = min(iter->count,
			       iter->iov->iov_len - iter->iov_offset),
	};
}

#define iov_for_each(iov, iter, start)				\
	for (iter = (start);					\
	     (iter).count &&					\
	     ((iov = iov_iter_iovec(&(iter))), 1);		\
	     iov_iter_advance(&(iter), (iov).iov_len))

unsigned long iov_shorten(struct iovec *iov, unsigned long nr_segs, size_t to);

size_t iov_iter_copy_from_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes);
void iov_iter_advance(struct iov_iter *i, size_t bytes);
int iov_iter_fault_in_readable(struct iov_iter *i, size_t bytes);
size_t iov_iter_single_seg_count(const struct iov_iter *i);
size_t copy_page_to_iter(struct page *page, size_t offset, size_t bytes,
			 struct iov_iter *i);
unsigned long iov_iter_alignment(const struct iov_iter *i);
void iov_iter_init(struct iov_iter *i, int direction, const struct iovec *iov,
			unsigned long nr_segs, size_t count);
ssize_t iov_iter_get_pages(struct iov_iter *i, struct page **pages,
			size_t maxsize, size_t *start);
ssize_t iov_iter_get_pages_alloc(struct iov_iter *i, struct page ***pages,
			size_t maxsize, size_t *start);
int iov_iter_npages(const struct iov_iter *i, int maxpages);

static inline size_t iov_iter_count(struct iov_iter *i)
{
	return i->count;
}

static inline void iov_iter_truncate(struct iov_iter *i, size_t count)
{
	if (i->count > count)
		i->count = count;
}

int memcpy_fromiovec(unsigned char *kdata, struct iovec *iov, int len);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,6 +68,8 @@
 size_t iov_iter_single_seg_count(const struct iov_iter *i);
 size_t copy_page_to_iter(struct page *page, size_t offset, size_t bytes,
 			 struct iov_iter *i);
+size_t copy_page_from_iter(struct page *page, size_t offset, size_t bytes,
+			 struct iov_iter *i);
 unsigned long iov_iter_alignment(const struct iov_iter *i);
 void iov_iter_init(struct iov_iter *i, int direction, const struct iovec *iov,
 			unsigned long nr_segs, size_t count);
```
