# CrossVul Fix Pair: Protection Mechanism Failure in typescript
**Pair ID:** 4131_3
**Vulnerability Class:** Protection Mechanism Failure
**CWE:** CWE-693
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4131_3`)

## Vulnerability Information & PoC

## Description
Protection Mechanism Failure - This weakness covers three distinct situations.

## Vulnerable Code
```typescript
Lines 425-465 of the vulnerable file.

      const [, test] = await answer;
      expect(test).to.equal('test');
    });
  });

  for (const sandbox of [false, true]) {
    describe(`navigation events${sandbox ? ' with sandbox' : ''}`, () => {
      let w = null as unknown as BrowserWindow;
      beforeEach(() => {
        w = new BrowserWindow({ show: false, webPreferences: { nodeIntegration: false, sandbox } });
      });
      afterEach(async () => {
        await closeWindow(w);
        w = null as unknown as BrowserWindow;
      });

      describe('will-navigate event', () => {
        let server = null as unknown as http.Server;
        let url = null as unknown as string;
        before((done) => {
          server = http.createServer((req, res) => { res.end(''); });
          server.listen(0, '127.0.0.1', () => {
            url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
            done();
          });
        });

        after(() => {
          server.close();
        });

        it('allows the window to be closed from the event listener', (done) => {
          w.webContents.once('will-navigate', () => {
            w.close();
            done();
          });
          w.loadFile(path.join(fixtures, 'pages', 'will-navigate.html'));
        });

        it('can be prevented', (done) => {
          let willNavigate = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -442,7 +442,13 @@
         let server = null as unknown as http.Server;
         let url = null as unknown as string;
         before((done) => {
-          server = http.createServer((req, res) => { res.end(''); });
+          server = http.createServer((req, res) => {
+            if (req.url === '/navigate-top') {
+              res.end('<a target=_top href="/">navigate _top</a>');
+            } else {
+              res.end('');
+            }
+          });
           server.listen(0, '127.0.0.1', () => {
             url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
             done();
@@ -505,6 +511,38 @@
           });
           expect(navigatedTo).to.equal(url);
           expect(w.webContents.getURL()).to.equal('about:blank');
+        });
+
+        it('is triggered when a cross-origin iframe navigates _top', async () => {
+          await w.loadURL(`data:text/html,<iframe src="http://127.0.0.1:${(server.address() as AddressInfo).port}/navigate-top"></iframe>`);
+          await delay(1000);
+          w.webContents.debugger.attach('1.1');
+          const targets = await w.webContents.debugger.sendCommand('Target.getTargets');
+          const iframeTarget = targets.targetInfos.find((t: any) => t.type === 'iframe');
+          const { sessionId } = await w.webContents.debugger.sendCommand('Target.attachToTarget', {
+            targetId: iframeTarget.targetId,
+            flatten: true
+          });
+          await w.webContents.debugger.sendCommand('Input.dispatchMouseEvent', {
+            type: 'mousePressed',
+            x: 10,
+            y: 10,
+            clickCount: 1,
+            button: 'left'
+          }, sessionId);
+          await w.webContents.debugger.sendCommand('Input.dispatchMouseEvent', {
+            type: 'mouseReleased',
+            x: 10,
+            y: 10,
+            clickCount: 1,
+            button: 'left'
+          }, sessionId);
+          let willNavigateEmitted = false;
+          w.webContents.on('will-navigate', () => {
+            willNavigateEmitted = true;
+          });
+          await emittedOnce(w.webContents, 'did-navigate');
+          expect(willNavigateEmitted).to.be.true();
         });
       });
 
```
