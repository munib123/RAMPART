# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 2007_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2007_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-21 of the vulnerable file.

const exec = require('async-execute');

/**
 * Create and push a git tag with the last commit message
 * @param  {String} tag
 * @return {void}
 */
module.exports = async function(tag) {
	if (!tag || ![ 'string', 'number' ].includes(typeof tag)) {
		throw new TypeError(`string was expected, instead got ${tag}`);
	}

	const { message, author, email } = this;

	await Promise.all([
		exec(`git config user.name "${await author}"`),
		exec(`git config user.email "${await email}"`),
	]);
	await exec(`git tag -a ${tag} -m "${await message}"`);
	await exec(`git push origin refs/tags/${tag}`);
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,6 @@
 		exec(`git config user.name "${await author}"`),
 		exec(`git config user.email "${await email}"`),
 	]);
-	await exec(`git tag -a ${tag} -m "${await message}"`);
-	await exec(`git push origin refs/tags/${tag}`);
+	await exec(`git tag -a ${JSON.stringify(tag)} -m "${await message}"`);
+	await exec(`git push origin ${JSON.stringify(`refs/tags/${tag}`)}`);
 };
```
