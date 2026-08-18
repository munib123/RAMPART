# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in typescript
**Pair ID:** 4629_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4629_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```typescript
Lines 16-56 of the vulnerable file.

    });

    it(`should resolve the styles from the SCSS theme`, () => {
      const scssStyles = METADATA['metadata']['BazComponent']['decorators'][0]['arguments'][0]['styles'][0];
      expect(scssStyles).to.contain(`color:red`);
      expect(scssStyles).to.contain(`background-color:#ff0`);
    });

    it(`should autoprefix scss based on the config in .browserslistrc`, () => {
      const scssStyles = METADATA['metadata']['BazComponent']['decorators'][0]['arguments'][0]['styles'][0];
      expect(scssStyles).to.contain(`display:flex`);
      expect(scssStyles).to.contain(`display:-ms-flexbox`);
    });

    it(`should resolve the styles from the Less theme`, () => {
      const lessStyles = METADATA['metadata']['BazComponent']['decorators'][0]['arguments'][0]['styles'][1];
      expect(lessStyles).to.contain(`.baz .oom`);
      expect(lessStyles).to.contain(`color:red`);
    });

    it(`should resolve the styles from the Less 'node_module' file ~`, () => {
      const lessStyles = METADATA['metadata']['BazComponent']['decorators'][0]['arguments'][0]['styles'][1];
      expect(lessStyles).to.contain(`tst3`);
    });

    it(`should resolve the styles from the Stylus theme`, () => {
      const stylusStyles = METADATA['metadata']['BazComponent']['decorators'][0]['arguments'][0]['styles'][2];
      expect(stylusStyles).to.contain(`font-size:32pt`);
    });

    it(`should resolve the styles from the SASS theme`, () => {
      const scssStyles = METADATA['metadata']['BazComponent']['decorators'][0]['arguments'][0]['styles'][0];
      expect(scssStyles).to.contain(`color:#00f`);
      expect(scssStyles).to.contain(`background-color:#ff0`);
    });

    it(`should autoprefix sass based on the config in .browserslistrc`, () => {
      const scssStyles = METADATA['metadata']['BazComponent']['decorators'][0]['arguments'][0]['styles'][3];
      expect(scssStyles).to.contain(`display:flex`);
      expect(scssStyles).to.contain(`display:-ms-flexbox`);
    });
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,7 +33,7 @@
       expect(lessStyles).to.contain(`color:red`);
     });
 
-    it(`should resolve the styles from the Less 'node_module' file ~`, () => {
+    xit(`should resolve the styles from the Less 'node_module' file ~`, () => {
       const lessStyles = METADATA['metadata']['BazComponent']['decorators'][0]['arguments'][0]['styles'][1];
       expect(lessStyles).to.contain(`tst3`);
     });
```
