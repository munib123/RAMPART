# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 714_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `714_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 11-51 of the vulnerable file.

// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const express = require('express');
const { exec } = require('child_process');

const utils = require('./utils');

const { FESTIVAL_BIN, TEXT_TO_WAV_BIN } = require('./constants');

const router = express.Router();

/** GET for healthcheck */
router.get('/healthz', (_req, res) => res.json('OK'));

/** GET alignment information of the synthesized text. */
router.get('/alignment', (req, res) => {
  const { text } = req.query;
  // TODO(twattanavekin): Test Unicode text.
  const escapedText = JSON.stringify(text).slice(1, -1);

  const { festvoxFile, voiceName, localFolder } = utils.getVoiceSettings();

  // Example command:
  // ${FESTIVALDIR}/bin/festival
  // -b festvox/goog_vb_unison_cg.scm  -b "(voice_goog_vb_unison_cg)"
  // -b "(Parameter.set 'Audio_Method 'Audio_Command)"
  // -b "(Parameter.set 'Audio_Command \"\")"
  // -b "(utt.relation.print (SayText \" hello \") 'Segment)"

  const cmd = `${FESTIVAL_BIN} -b ${festvoxFile}  -b "(${voiceName})" \
  -b "(Parameter.set 'Audio_Method 'Audio_Command)" \
  -b "(Parameter.set 'Audio_Command \\"\\")" \
  -b "(utt.relation.print (SayText \\" ${escapedText} \\") 'Segment)"`;

  const options = {
    cwd: localFolder,
    timeout: 10000,
    encoding: 'buffer',
  };
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,21 +28,22 @@
 router.get('/alignment', (req, res) => {
   const { text } = req.query;
   // TODO(twattanavekin): Test Unicode text.
-  const escapedText = JSON.stringify(text).slice(1, -1);
+  const sanitizedText = utils.replaceCharactersWithSpaces(text);
 
   const { festvoxFile, voiceName, localFolder } = utils.getVoiceSettings();
 
   // Example command:
+  // read txt; TEXT=${txt};
   // ${FESTIVALDIR}/bin/festival
   // -b festvox/goog_vb_unison_cg.scm  -b "(voice_goog_vb_unison_cg)"
   // -b "(Parameter.set 'Audio_Method 'Audio_Command)"
   // -b "(Parameter.set 'Audio_Command \"\")"
-  // -b "(utt.relation.print (SayText \" hello \") 'Segment)"
+  // -b "(utt.relation.print (SayText \" ${TEXT} \") 'Segment)";
 
-  const cmd = `${FESTIVAL_BIN} -b ${festvoxFile}  -b "(${voiceName})" \
+  const cmd = `read txt; TEXT=\$\{txt\}; ${FESTIVAL_BIN} -b ${festvoxFile}  -b "(${voiceName})" \
   -b "(Parameter.set 'Audio_Method 'Audio_Command)" \
   -b "(Parameter.set 'Audio_Command \\"\\")" \
-  -b "(utt.relation.print (SayText \\" ${escapedText} \\") 'Segment)"`;
+  -b "(utt.relation.print (SayText \\" \$\{TEXT\} \\") 'Segment)";`;
 
   const options = {
     cwd: localFolder,
@@ -52,30 +53,31 @@
 
   console.log(`Running command - \n${cmd}`);
 
-  exec(cmd, options, (err, stdout, stderr) => {
+  const child = exec(cmd, options, (err, stdout, stderr) => {
     const errMsg = utils.getExecErrorMessage(err, stderr);
     if (errMsg) {
       return res.status(500).send(errMsg);
     }
     return res.status(200).send(utils.getAlignmentData(stdout.toString()));
   });
+  child.stdin.write(sanitizedText);
+  child.stdin.end();
 });
 
 /** GET synthesize voice based on a voice model */
 router.get('/tts', (req, res) => {
   const { text, type } = req.query;
   // TODO(twattanavekin): Test Unicode text.
-  const escapedText = JSON.stringify(text).slice(1, -1);
+  const sanitizedText = utils.replaceCharactersWithSpaces(text);
+  console.log(`Synthesizing ${sanitizedText}`);
 
-  console.log(`Synthesize "${text}"`);
   const { festvoxFile, voiceName, localFolder } = utils.getVoiceSettings();
 
   // Example command:
-  // echo "Hello world" | festival/bin/text2wave \
+  // festival/bin/text2wave \
   //  -eval festvox/goog_vb_unison_cg.scm \
   //  -eval "(voice_vb_unison_cg)"
-  const cmd = `echo "${escapedText}" \
-              | ${TEXT_TO_WAV_BIN} -eval ${festvoxFile} -eval "(${voiceName})"`;
+  const cmd = `${TEXT_TO_WAV_BIN} -eval ${festvoxFile} -eval "(${voiceName})"`;
   console.log(`Running command - \n${cmd}`);
 
   const options = {
@@ -83,7 +85,8 @@
     timeout: 10000,
     encoding: 'buffer',
   };
-  exec(cmd, options, (err, stdout, stderr) => {
+
+  const child = exec(cmd, options, (err, stdout, stderr) => {
     const errMsg = utils.getExecErrorMessage(err, stderr);
     if (errMsg) {
       return res.status(500).send(errMsg);
@@ -93,6 +96,8 @@
     const data = type === 'base64' ? stdout.toString('base64') : stdout;
     return res.send(data);
   });
+  child.stdin.write(sanitizedText);
+  child.stdin.end();
 });
 
 module.exports = router;
```
