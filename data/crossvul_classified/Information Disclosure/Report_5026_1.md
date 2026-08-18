# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 5026_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5026_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 268-308 of the vulnerable file.


  log.verbose('cache add', 'spec', spec)

  if (!spec) return cb(usage)

  adding++
  cb = afterAdd(cb)

  realizePackageSpecifier(spec, where, function (err, p) {
    if (err) return cb(err)

    log.silly('cache add', 'parsed spec', p)

    switch (p.type) {
      case 'local':
      case 'directory':
        addLocal(p, null, cb)
        break
      case 'remote':
        // get auth, if possible
        mapToRegistry(spec, npm.config, function (err, uri, auth) {
          if (err) return cb(err)

          addRemoteTarball(p.spec, { name: p.name }, null, auth, cb)
        })
        break
      case 'git':
      case 'hosted':
        addRemoteGit(p.rawSpec, cb)
        break
      default:
        if (p.name) return addNamed(p.name, p.spec, null, cb)

        cb(new Error("couldn't figure out how to install " + spec))
    }
  })
}

function unpack (pkg, ver, unpackTarget, dMode, fMode, uid, gid, cb) {
  if (typeof cb !== 'function') {
    cb = gid
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -285,7 +285,7 @@
         break
       case 'remote':
         // get auth, if possible
-        mapToRegistry(spec, npm.config, function (err, uri, auth) {
+        mapToRegistry(p.raw, npm.config, function (err, uri, auth) {
           if (err) return cb(err)
 
           addRemoteTarball(p.spec, { name: p.name }, null, auth, cb)
```
