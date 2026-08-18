# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 2007_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2007_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 14-37 of the vulnerable file.

			email: 'boaty@boat.face',
		});
	});

	after(() => clean('.'));

	it('Should use a given user', async() => {
		const lines = [];
		dummy.stub = command => lines.push(command);

		await gitTag('1.1.1');
		expect(lines).to.include('git config user.name "boaty mcboatface"');
		expect(lines).to.include('git config user.email "boaty@boat.face"');
	});

	it('Should create a git tag with given message and push it', async() => {
		const lines = [];
		dummy.stub = command => lines.push(command);

		await gitTag('1.1.1');
		expect(lines).to.include('git tag -a 1.1.1 -m "this is a message"');
		expect(lines).to.include('git push origin refs/tags/1.1.1');
	});
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,7 @@
 		dummy.stub = command => lines.push(command);
 
 		await gitTag('1.1.1');
-		expect(lines).to.include('git tag -a 1.1.1 -m "this is a message"');
-		expect(lines).to.include('git push origin refs/tags/1.1.1');
+		expect(lines).to.include('git tag -a "1.1.1" -m "this is a message"');
+		expect(lines).to.include('git push origin "refs/tags/1.1.1"');
 	});
 });
```
