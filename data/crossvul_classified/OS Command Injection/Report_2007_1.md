# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 2007_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2007_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 15-52 of the vulnerable file.

	it('Should only accept string as sha', async() => {
		const types = [
			null,
			122,
			[ 1, 2, 3 ],
			{ a: 1 },
			/regexp/,
		];
		for (let t of types) {
			try {
				await reset(t);
				assert(false, `should fail with ${t}`);
			} catch (error) {
				expect(error).to.be.instanceOf(TypeError);
			}
		}
	});

	it('Should hard reset to a given sha', async() => {
		reset('shaid');
		expect(exec.getCall(0).args[0]).to.equal('git reset shaid --hard');
	});

	it('Should hard reset to n commits back', async() => {
		reset(1);
		expect(exec.getCall(0).args[0]).to.equal('git reset HEAD~1 --hard');
	});

	it('Should hard reset to n commits back with negative value as well', async() => {
		reset(-3);
		expect(exec.getCall(0).args[0]).to.equal('git reset HEAD~3 --hard');
	});

	it('Should reset w/o hard argument', async() => {
		reset('shaid', { hard: false });
		expect(exec.getCall(0).args[0].trim()).to.equal('git reset shaid');
	});
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
 
 	it('Should hard reset to a given sha', async() => {
 		reset('shaid');
-		expect(exec.getCall(0).args[0]).to.equal('git reset shaid --hard');
+		expect(exec.getCall(0).args[0]).to.equal('git reset "shaid" --hard');
 	});
 
 	it('Should hard reset to n commits back', async() => {
@@ -47,6 +47,6 @@
 
 	it('Should reset w/o hard argument', async() => {
 		reset('shaid', { hard: false });
-		expect(exec.getCall(0).args[0].trim()).to.equal('git reset shaid');
+		expect(exec.getCall(0).args[0].trim()).to.equal('git reset "shaid"');
 	});
 });
```
