# CrossVul Fix Pair: Modification of Assumed-Immutable Data (MAID) in javascript
**Pair ID:** 4355_2
**Vulnerability Class:** Modification of Assumed-Immutable Data (MAID)
**CWE:** CWE-471
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4355_2`)

## Vulnerability Information & PoC

## Description
Modification of Assumed-Immutable Data (MAID) - This occurs when a particular input is critical enough to the functioning of the application that it should not be modifiable at all, but it is.

## Vulnerable Code
```javascript
Lines 24-44 of the vulnerable file.


  it('should return undefined', () => {
    const result = hljs.getLanguage('-impossible-');

    should.strictEqual(result, undefined);
  });

  it('should not break on undefined', () => {
    const result = hljs.getLanguage(undefined);

    should.strictEqual(result, undefined);
  });

  it('should get the csharp language by c# alias', () => {
    const result = hljs.getLanguage('c#');

    result.should.be.instanceOf(Object);
    result.should.have.property('aliases').with.containEql('cs');
    should.strictEqual(result, hljs.getLanguage('csharp'))
  });
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,4 +41,16 @@
     result.should.have.property('aliases').with.containEql('cs');
     should.strictEqual(result, hljs.getLanguage('csharp'))
   });
+
+  it('should not succeed for constructor', () => {
+    const result = hljs.getLanguage('constructor');
+
+    should.strictEqual(result, undefined);
+  });
+
+  it('should not succeed for __proto__', () => {
+    const result = hljs.getLanguage('__proto__');
+
+    should.strictEqual(result, undefined);
+  });
 });
```
