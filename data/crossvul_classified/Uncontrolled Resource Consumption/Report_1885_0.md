# CrossVul Fix Pair: Uncontrolled Resource Consumption in rust
**Pair ID:** 1885_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1885_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```rust
Lines 39-79 of the vulnerable file.

pub fn read16<R>(reader: &mut R) -> Result<u16, io::Error> where R: io::Read {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

pub fn read64<R>(reader: &mut R) -> Result<u64, io::Error> where R: io::Read {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

pub trait BufReadExt {
    fn discard_exact(&mut self, len: usize) -> io::Result<()>;
}

impl<T> BufReadExt for T where T: io::BufRead {
    fn discard_exact(&mut self, mut len: usize) -> io::Result<()> {
        while len > 0 {
            let consume_len = match self.fill_buf() {
                Ok(buf) => buf.len().min(len),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            self.consume(consume_len);
            len -= consume_len;
        }
        Ok(())
    }
}

// This function must not be called with more than 4 bytes.
pub fn atou16(bytes: &[u8]) -> Result<u16, Error> {
    if cfg!(debug_assertions) && bytes.len() >= 5 {
        panic!("atou16 accepts up to 4 bytes");
    }
    if bytes.len() == 0 {
        return Err(Error::InvalidFormat("Not a number"));
    }
    let mut n = 0;
    for &c in bytes {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,9 @@
     fn discard_exact(&mut self, mut len: usize) -> io::Result<()> {
         while len > 0 {
             let consume_len = match self.fill_buf() {
+                Ok(buf) if buf.is_empty() =>
+                    return Err(io::Error::new(
+                        io::ErrorKind::UnexpectedEof, "unexpected EOF")),
                 Ok(buf) => buf.len().min(len),
                 Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                 Err(e) => return Err(e),
@@ -100,6 +103,16 @@
     use super::*;
 
     #[test]
+    fn discard_exact() {
+        let mut buf = b"abc".as_ref();
+        buf.discard_exact(1).unwrap();
+        assert_eq!(buf, b"bc");
+        buf.discard_exact(2).unwrap();
+        assert_eq!(buf, b"");
+        buf.discard_exact(1).unwrap_err();
+    }
+
+    #[test]
     fn read8_len() {
         let mut reader = Cursor::new([]);
         assert_err_kind!(read8(&mut reader), ErrorKind::UnexpectedEof);
```
