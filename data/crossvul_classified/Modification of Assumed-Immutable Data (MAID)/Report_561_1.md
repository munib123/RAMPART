# CrossVul Fix Pair: Modification of Assumed-Immutable Data (MAID) in javascript
**Pair ID:** 561_1
**Vulnerability Class:** Modification of Assumed-Immutable Data (MAID)
**CWE:** CWE-471
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `561_1`)

## Vulnerability Information & PoC

## Description
Modification of Assumed-Immutable Data (MAID) - This occurs when a particular input is critical enough to the functioning of the application that it should not be modifiable at all, but it is.

## Vulnerable Code
```javascript
Lines 567-607 of the vulnerable file.

        const a = { x: new Date(1378776452757) };

        const b = Hoek.merge({}, a);
        expect(a.x.getTime()).to.equal(b.x.getTime());
    });

    it('retains Date properties when merging keys', () => {

        const a = { x: new Date(1378776452757) };

        const b = Hoek.merge({ x: {} }, a);
        expect(a.x.getTime()).to.equal(b.x.getTime());
    });

    it('overrides Buffer', () => {

        const a = { x: Buffer.from('abc') };

        Hoek.merge({ x: {} }, a);
        expect(a.x.toString()).to.equal('abc');
    });
});

describe('applyToDefaults()', () => {

    const defaults = {
        a: 1,
        b: 2,
        c: {
            d: 3,
            e: [5, 6]
        },
        f: 6,
        g: 'test'
    };

    it('throws when target is null', () => {

        expect(() => {

            Hoek.applyToDefaults(null, {});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -584,6 +584,15 @@
 
         Hoek.merge({ x: {} }, a);
         expect(a.x.toString()).to.equal('abc');
+    });
+
+    it('skips __proto__', () => {
+
+        const a = '{ "ok": "value", "__proto__": { "test": "value" } }';
+
+        const b = Hoek.merge({}, JSON.parse(a));
+        expect(b).to.equal({ ok: 'value' });
+        expect(b.test).to.equal(undefined);
     });
 });
 
```
