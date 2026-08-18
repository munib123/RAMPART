# CrossVul Fix Pair: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') in rust
**Pair ID:** 1035_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-88
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1035_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - When creating commands using interpolation into a string, developers may assume that only the arguments/options that they specify will be processed.

## Vulnerable Code
```rust
Lines 162-202 of the vulnerable file.

            back,
            sent_http_response: false,
        }
    }

    /// We're a connection, and we have something to do.
    fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::Event) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        if ev.readiness().is_readable() {
            self.do_tls_read();
            self.try_plain_read();
            self.try_back_read();
        }

        if ev.readiness().is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing && !self.tls_session.wants_write() {
            let _ = self.socket.shutdown(Shutdown::Both);
            self.close_back();
            self.closed = true;
        } else {
            self.reregister(poll);
        }
    }

    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if self.back.is_some() {
            let back = self.back.as_mut().unwrap();
            back.shutdown(Shutdown::Both).unwrap();
        }
        self.back = None;
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        let rc = self.tls_session.read_tls(&mut self.socket);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -179,7 +179,7 @@
             self.do_tls_write_and_handle_error();
         }
 
-        if self.closing && !self.tls_session.wants_write() {
+        if self.closing {
             let _ = self.socket.shutdown(Shutdown::Both);
             self.close_back();
             self.closed = true;
```
