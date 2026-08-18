# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2816_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2816_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 590-630 of the vulnerable file.

        if not channel:
            channel = salt.transport.client.AsyncReqChannel.factory(self.opts,
                                                                crypt='clear',
                                                                io_loop=self.io_loop)

        sign_in_payload = self.minion_sign_in_payload()
        try:
            payload = yield channel.send(
                sign_in_payload,
                tries=tries,
                timeout=timeout
            )
        except SaltReqTimeoutError as e:
            if safe:
                log.warning('SaltReqTimeoutError: {0}'.format(e))
                raise tornado.gen.Return('retry')
            if self.opts.get('detect_mode') is True:
                raise tornado.gen.Return('retry')
            else:
                raise SaltClientError('Attempt to authenticate with the salt master failed with timeout error')
        if 'load' in payload:
            if 'ret' in payload['load']:
                if not payload['load']['ret']:
                    if self.opts['rejected_retry']:
                        log.error(
                            'The Salt Master has rejected this minion\'s public '
                            'key.\nTo repair this issue, delete the public key '
                            'for this minion on the Salt Master.\nThe Salt '
                            'Minion will attempt to to re-authenicate.'
                        )
                        raise tornado.gen.Return('retry')
                    else:
                        log.critical(
                            'The Salt Master has rejected this minion\'s public '
                            'key!\nTo repair this issue, delete the public key '
                            'for this minion on the Salt Master and restart this '
                            'minion.\nOr restart the Salt Master in open mode to '
                            'clean out the keys. The Salt Minion will now exit.'
                        )
                        sys.exit(salt.defaults.exitcodes.EX_OK)
                # has the master returned that its maxed out with minions?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -607,6 +607,9 @@
                 raise tornado.gen.Return('retry')
             else:
                 raise SaltClientError('Attempt to authenticate with the salt master failed with timeout error')
+        if not isinstance(payload, dict):
+            log.error('Sign-in attempt failed: %s', payload)
+            raise tornado.gen.Return(False)
         if 'load' in payload:
             if 'ret' in payload['load']:
                 if not payload['load']['ret']:
```
