# CrossVul Fix Pair: Origin Validation Error in javascript
**Pair ID:** 2992_5
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2992_5`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```javascript
Lines 13-53 of the vulnerable file.


// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

import { Quantity, Data } from '../types';
import { fromDecimal, Dummy } from '../helpers';

export default {
  generateAuthorizationToken: {
    desc: 'Generates a new authorization token.',
    params: [],
    returns: {
      type: String,
      desc: 'The new authorization token.',
      example: 'bNGY-iIPB-j7zK-RSYZ'
    }
  },

  generateWebProxyAccessToken: {
    desc: 'Generates a new web proxy access token.',
    params: [],
    returns: {
      type: String,
      desc: 'The new web proxy access token.',
      example: 'MOWm0tEJjwthDiTU'
    }
  },

  requestsToConfirm: {
    desc: 'Returns a list of the transactions awaiting authorization.',
    params: [],
    returns: {
      // TODO: Types of the fields of transaction objects? Link to a transaction object in another page?
      type: Array,
      desc: 'A list of the outstanding transactions.',
      example: new Dummy('[ ... ]')
    }
  },

  confirmRequest: {
    desc: 'Confirm a request in the signer queue',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,11 @@
 
   generateWebProxyAccessToken: {
     desc: 'Generates a new web proxy access token.',
-    params: [],
+    params: [{
+      type: String,
+      desc: 'Domain for which the token is valid. Only requests to this domain will be allowed.',
+      example: 'https://parity.io'
+    }],
     returns: {
       type: String,
       desc: 'The new web proxy access token.',
```
