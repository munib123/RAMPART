# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 2007_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2007_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-19 of the vulnerable file.

const exec = require('async-execute');

/**
 * Reset current HEAD to the specified state
 * @param  {String|Number}  destination
 * @param  {Boolean} options.hard
 * @return {void}
 */
module.exports = async function(destination, { hard = true } = {}) {
	if (destination && typeof destination === 'string') {
		return await exec(`git reset ${destination} ${hard ? '--hard' : ''}`);
	}

	if (destination && typeof destination === 'number') {
		return await exec(`git reset HEAD~${Math.abs(destination)} ${hard ? '--hard' : ''}`);
	}

	throw new TypeError(`No case for handling destination ${destination} (${typeof destination})`);
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
  */
 module.exports = async function(destination, { hard = true } = {}) {
 	if (destination && typeof destination === 'string') {
-		return await exec(`git reset ${destination} ${hard ? '--hard' : ''}`);
+		return await exec(`git reset ${JSON.stringify(destination)} ${hard ? '--hard' : ''}`);
 	}
 
 	if (destination && typeof destination === 'number') {
```
