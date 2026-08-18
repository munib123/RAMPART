# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in javascript
**Pair ID:** 532_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `532_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```javascript
Lines 2269-2288 of the vulnerable file.

  }

  t.test('sync', t => {
    const dir = path.join(basedir, 'sync')
    mkdirp.sync(dir)
    const unpack = new UnpackSync({ cwd: dir, onentry })
    unpack.end(data)
    check(t)
  })

  t.test('async', t => {
    const dir = path.join(basedir, 'async')
    mkdirp.sync(dir)
    const unpack = new Unpack({ cwd: dir, onentry })
    unpack.on('finish', () => check(t))
    unpack.end(data)
  })

  t.end()
})
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2286,3 +2286,66 @@
 
   t.end()
 })
+
+t.test('do not reuse hardlinks, only nlink=1 files', t => {
+  const basedir = path.resolve(unpackdir, 'hardlink-reuse')
+  mkdirp.sync(basedir)
+  t.teardown(() => rimraf.sync(basedir))
+
+  const now = new Date('2018-04-30T18:30:39.025Z')
+
+  const data = makeTar([
+    {
+      path: 'overwriteme',
+      type: 'File',
+      size: 4,
+      mode: 0o644,
+      mtime: now
+    },
+    'foo\n',
+    {
+      path: 'link',
+      linkpath: 'overwriteme',
+      type: 'Link',
+      mode: 0o644,
+      mtime: now
+    },
+    {
+      path: 'link',
+      type: 'File',
+      size: 4,
+      mode: 0o644,
+      mtime: now
+    },
+    'bar\n',
+    '',
+    ''
+  ])
+
+  const checks = {
+    'link': 'bar\n',
+    'overwriteme': 'foo\n'
+  }
+
+  const check = t => {
+    for (let f in checks) {
+      t.equal(fs.readFileSync(basedir + '/' + f, 'utf8'), checks[f], f)
+      t.equal(fs.statSync(basedir + '/' + f).nlink, 1, f)
+    }
+    t.end()
+  }
+
+  t.test('async', t => {
+    const u = new Unpack({ cwd: basedir })
+    u.on('close', () => check(t))
+    u.end(data)
+  })
+
+  t.test('sync', t => {
+    const u = new UnpackSync({ cwd: basedir })
+    u.end(data)
+    check(t)
+  })
+
+  t.end()
+})
```
