# CrossVul Fix Pair: 7PK in python
**Pair ID:** 1020_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1020_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```python
Lines 3606-3646 of the vulnerable file.

        if stream:  # not double-detach()'d
            os.setsid()
            self.parent.send_await(Message(handle=DETACHING))
            LOG.info('Detaching from %r; parent is %s', stream, self.parent)
            for x in range(20):
                pending = self.broker.defer_sync(stream.protocol.pending_bytes)
                if not pending:
                    break
                time.sleep(0.05)
            if pending:
                LOG.error('Stream had %d bytes after 2000ms', pending)
            self.broker.defer(stream.on_disconnect, self.broker)

    def _setup_master(self):
        Router.max_message_size = self.config['max_message_size']
        if self.config['profiling']:
            enable_profiling()
        self.broker = Broker(activate_compat=False)
        self.router = Router(self.broker)
        self.router.debug = self.config.get('debug', False)
        self.router.undirectional = self.config['unidirectional']
        self.router.add_handler(
            fn=self._on_shutdown_msg,
            handle=SHUTDOWN,
            policy=has_parent_authority,
        )
        self.master = Context(self.router, 0, 'master')
        parent_id = self.config['parent_ids'][0]
        if parent_id == 0:
            self.parent = self.master
        else:
            self.parent = Context(self.router, parent_id, 'parent')

        in_fd = self.config.get('in_fd', 100)
        in_fp = os.fdopen(os.dup(in_fd), 'rb', 0)
        os.close(in_fd)

        out_fp = os.fdopen(os.dup(self.config.get('out_fd', 1)), 'wb', 0)
        self.stream = MitogenProtocol.build_stream(self.router, parent_id)
        self.stream.accept(in_fp, out_fp)
        self.stream.name = 'parent'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3623,7 +3623,7 @@
         self.broker = Broker(activate_compat=False)
         self.router = Router(self.broker)
         self.router.debug = self.config.get('debug', False)
-        self.router.undirectional = self.config['unidirectional']
+        self.router.unidirectional = self.config['unidirectional']
         self.router.add_handler(
             fn=self._on_shutdown_msg,
             handle=SHUTDOWN,
```
