# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2816_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2816_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 579-619 of the vulnerable file.

        except Exception as exc:
            exc_type = type(exc).__name__
            if exc_type == 'AuthenticationError':
                log.debug(
                    'Minion failed to auth to master. Since the payload is '
                    'encrypted, it is not known which minion failed to '
                    'authenticate. It is likely that this is a transient '
                    'failure due to the master rotating its public key.'
                )
            else:
                log.error('Bad load from minion: %s: %s', exc_type, exc)
            stream.send(self.serial.dumps('bad load'))
            raise tornado.gen.Return()

        # TODO helper functions to normalize payload?
        if not isinstance(payload, dict) or not isinstance(payload.get('load'), dict):
            log.error('payload and load must be a dict. Payload was: {0} and load was {1}'.format(payload, payload.get('load')))
            stream.send(self.serial.dumps('payload and load must be a dict'))
            raise tornado.gen.Return()

        # intercept the "_auth" commands, since the main daemon shouldn't know
        # anything about our key auth
        if payload['enc'] == 'clear' and payload.get('load', {}).get('cmd') == '_auth':
            stream.send(self.serial.dumps(self._auth(payload['load'])))
            raise tornado.gen.Return()

        # TODO: test
        try:
            # Take the payload_handler function that was registered when we created the channel
            # and call it, returning control to the caller until it completes
            ret, req_opts = yield self.payload_handler(payload)
        except Exception as e:
            # always attempt to return an error to the minion
            stream.send('Some exception handling minion payload')
            log.error('Some exception handling a payload from minion', exc_info=True)
            raise tornado.gen.Return()

        req_fun = req_opts.get('fun', 'send')
        if req_fun == 'send_clear':
            stream.send(self.serial.dumps(ret))
        elif req_fun == 'send':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -594,6 +594,17 @@
         if not isinstance(payload, dict) or not isinstance(payload.get('load'), dict):
             log.error('payload and load must be a dict. Payload was: {0} and load was {1}'.format(payload, payload.get('load')))
             stream.send(self.serial.dumps('payload and load must be a dict'))
+            raise tornado.gen.Return()
+
+        try:
+            id_ = payload['load'].get('id', '')
+            if '\0' in id_:
+                log.error('Payload contains an id with a null byte: %s', payload)
+                stream.send(self.serial.dumps('bad load: id contains a null byte'))
+                raise tornado.gen.Return()
+        except TypeError:
+            log.error('Payload contains non-string id: %s', payload)
+            stream.send(self.serial.dumps('bad load: id {0} is not a string'.format(id_)))
             raise tornado.gen.Return()
 
         # intercept the "_auth" commands, since the main daemon shouldn't know
```
