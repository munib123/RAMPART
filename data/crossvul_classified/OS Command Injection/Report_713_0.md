# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 713_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `713_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 16-57 of the vulnerable file.

const { exec } = require('child_process');

const utils = require('./utils');

const { SYNTH_SCRIPT } = require('./constants');

const router = express.Router();

/** GET for healthcheck */
router.get('/healthz', (_req, res) => res.json('OK'));

/**
* GET alignment information of the synthesized text.
* TODO: Implement alignment.
*/
router.get('/alignment', (req, res) => res.status(200).send([]));

/** GET synthesize voice based on a voice model */
router.get('/tts', (req, res) => {
  const { text, type } = req.query;
  // TODO(twattanavekin): Test Unicode text.
  const escapedText = JSON.stringify(text).slice(1, -1);

  // Example command:
  //  echo "hello" | ${SYNTH_SCRIPT}

  const cmd = `echo "${escapedText}" | ${SYNTH_SCRIPT}`;
  console.log(`Running command - \n${cmd}`);

  const options = {
    maxBuffer: 1024 * 1000, // 1 mb buffer
    cwd: '/tmp/',
    timeout: 60000, // 1 minute timeout
    encoding: 'buffer',
  };

  exec(cmd, options, (err, stdout, stderr) => {
    const errMsg = utils.getExecErrorMessage(err, stderr);
    if (errMsg) {
      return res.status(500).send(errMsg);
    }
    res.status(200);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,14 +33,9 @@
 /** GET synthesize voice based on a voice model */
 router.get('/tts', (req, res) => {
   const { text, type } = req.query;
-  // TODO(twattanavekin): Test Unicode text.
-  const escapedText = JSON.stringify(text).slice(1, -1);
+  const sanitizedText = utils.replaceCharactersWithSpaces(text);
 
-  // Example command:
-  //  echo "hello" | ${SYNTH_SCRIPT}
-
-  const cmd = `echo "${escapedText}" | ${SYNTH_SCRIPT}`;
-  console.log(`Running command - \n${cmd}`);
+  console.log(`Synthesizing ${sanitizedText}`);
 
   const options = {
     maxBuffer: 1024 * 1000, // 1 mb buffer
@@ -49,7 +44,7 @@
     encoding: 'buffer',
   };
 
-  exec(cmd, options, (err, stdout, stderr) => {
+  const child = exec(SYNTH_SCRIPT, options, (err, stdout, stderr) => {
     const errMsg = utils.getExecErrorMessage(err, stderr);
     if (errMsg) {
       return res.status(500).send(errMsg);
@@ -59,6 +54,8 @@
     const data = type === 'base64' ? stdout.toString('base64') : stdout;
     return res.send(data);
   });
+  child.stdin.write(sanitizedText);
+  child.stdin.end();
 });
 
 module.exports = router;
```
