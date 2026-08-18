# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2816_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2816_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 604-644 of the vulnerable file.

            self.req_server.add_socket(self._socket)
            self._socket.listen(self.backlog)
        salt.transport.mixins.auth.AESReqServerMixin.post_fork(self, payload_handler, io_loop)

    @tornado.gen.coroutine
    def handle_message(self, stream, header, payload):
        '''
        Handle incoming messages from underylying tcp streams
        '''
        try:
            try:
                payload = self._decode_payload(payload)
            except Exception:
                stream.write(salt.transport.frame.frame_msg('bad load', header=header))
                raise tornado.gen.Return()

            # TODO helper functions to normalize payload?
            if not isinstance(payload, dict) or not isinstance(payload.get('load'), dict):
                yield stream.write(salt.transport.frame.frame_msg(
                    'payload and load must be a dict', header=header))
                raise tornado.gen.Return()

            # intercept the "_auth" commands, since the main daemon shouldn't know
            # anything about our key auth
            if payload['enc'] == 'clear' and payload.get('load', {}).get('cmd') == '_auth':
                yield stream.write(salt.transport.frame.frame_msg(
                    self._auth(payload['load']), header=header))
                raise tornado.gen.Return()

            # TODO: test
            try:
                ret, req_opts = yield self.payload_handler(payload)
            except Exception as e:
                # always attempt to return an error to the minion
                stream.write('Some exception handling minion payload')
                log.error('Some exception handling a payload from minion', exc_info=True)
                stream.close()
                raise tornado.gen.Return()

            req_fun = req_opts.get('fun', 'send')
            if req_fun == 'send_clear':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -623,6 +623,17 @@
                     'payload and load must be a dict', header=header))
                 raise tornado.gen.Return()
 
+            try:
+                id_ = payload['load'].get('id', '')
+                if '\0' in id_:
+                    log.error('Payload contains an id with a null byte: %s', payload)
+                    stream.send(self.serial.dumps('bad load: id contains a null byte'))
+                    raise tornado.gen.Return()
+            except TypeError:
+                log.error('Payload contains non-string id: %s', payload)
+                stream.send(self.serial.dumps('bad load: id {0} is not a string'.format(id_)))
+                raise tornado.gen.Return()
+
             # intercept the "_auth" commands, since the main daemon shouldn't know
             # anything about our key auth
             if payload['enc'] == 'clear' and payload.get('load', {}).get('cmd') == '_auth':
```
