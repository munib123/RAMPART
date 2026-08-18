# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 85_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `85_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 544-584 of the vulnerable file.


  *failed = FALSE;
  if (fd < 0)
    return fd;

  new_fd = dup(fd);
  if (new_fd == -1) *failed = TRUE;
  return new_fd;
}

mrb_value
mrb_io_initialize_copy(mrb_state *mrb, mrb_value copy)
{
  mrb_value orig;
  mrb_value buf;
  struct mrb_io *fptr_copy;
  struct mrb_io *fptr_orig;
  mrb_bool failed = TRUE;

  mrb_get_args(mrb, "o", &orig);
  fptr_copy = (struct mrb_io *)DATA_PTR(copy);
  if (fptr_copy != NULL) {
    fptr_finalize(mrb, fptr_copy, FALSE);
    mrb_free(mrb, fptr_copy);
  }
  fptr_copy = (struct mrb_io *)mrb_io_alloc(mrb);
  fptr_orig = io_get_open_fptr(mrb, orig);

  DATA_TYPE(copy) = &mrb_io_type;
  DATA_PTR(copy) = fptr_copy;

  buf = mrb_iv_get(mrb, orig, mrb_intern_cstr(mrb, "@buf"));
  mrb_iv_set(mrb, copy, mrb_intern_cstr(mrb, "@buf"), buf);

  fptr_copy->fd = mrb_dup(mrb, fptr_orig->fd, &failed);
  if (failed) {
    mrb_sys_fail(mrb, 0);
  }
  mrb_fd_cloexec(mrb, fptr_copy->fd);

  if (fptr_orig->fd2 != -1) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -561,13 +561,13 @@
   mrb_bool failed = TRUE;
 
   mrb_get_args(mrb, "o", &orig);
+  fptr_orig = io_get_open_fptr(mrb, orig);
   fptr_copy = (struct mrb_io *)DATA_PTR(copy);
   if (fptr_copy != NULL) {
     fptr_finalize(mrb, fptr_copy, FALSE);
     mrb_free(mrb, fptr_copy);
   }
   fptr_copy = (struct mrb_io *)mrb_io_alloc(mrb);
-  fptr_orig = io_get_open_fptr(mrb, orig);
 
   DATA_TYPE(copy) = &mrb_io_type;
   DATA_PTR(copy) = fptr_copy;
```
