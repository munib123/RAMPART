# CrossVul Fix Pair: DEPRECATED: Use of Uninitialized Resource in cpp
**Pair ID:** 3343_0
**Vulnerability Class:** DEPRECATED- Use of Uninitialized Resource
**CWE:** CWE-1187
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3343_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Use of Uninitialized Resource - This entry has been deprecated because it was a duplicate of CWE-908.

## Vulnerable Code
```cpp
Lines 339-379 of the vulnerable file.

{
	return lbyte;
}

/* -----------------------------------------------
	gets current position from abytereader
	----------------------------------------------- */	

int abytereader::getpos( void )
{
	return cbyte;
}

bounded_iostream::bounded_iostream(Sirikata::DecoderWriter *w,
                                   const std::function<void(Sirikata::DecoderWriter*, size_t)> &size_callback,
                                   const Sirikata::JpegAllocator<uint8_t> &alloc) 
    : parent(w), err(Sirikata::JpegError::nil()) {
    this->size_callback = size_callback;
    buffer_position = 0;
    byte_position = 0;
    num_bytes_attempted_to_write = 0;
    set_bound(0);
}
void bounded_iostream::call_size_callback(size_t size) {
    size_callback(parent, size);
}
bool bounded_iostream::chkerr() {
    return err != Sirikata::JpegError::nil();
}

void bounded_iostream::set_bound(size_t bound) {
    flush();
    if (num_bytes_attempted_to_write > byte_bound) {
        num_bytes_attempted_to_write = byte_bound;
    }
    byte_bound = bound;
}
void bounded_iostream::flush() {
    if (buffer_position) {
        write_no_buffer(buffer, buffer_position);
        buffer_position = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -356,6 +356,7 @@
     this->size_callback = size_callback;
     buffer_position = 0;
     byte_position = 0;
+    byte_bound = 0x7FFFFFFF;
     num_bytes_attempted_to_write = 0;
     set_bound(0);
 }
@@ -384,7 +385,7 @@
     parent->Close();
 }
 
-unsigned int bounded_iostream::write_no_buffer(const void *from, size_t bytes_to_write) {
+uint32_t bounded_iostream::write_no_buffer(const void *from, size_t bytes_to_write) {
     //return iostream::write(from,tpsize,dtsize);
     std::pair<unsigned int, Sirikata::JpegError> retval;
     if (byte_bound != 0 && byte_position + bytes_to_write > byte_bound) {
```
