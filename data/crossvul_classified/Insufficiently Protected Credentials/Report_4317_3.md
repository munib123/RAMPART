# CrossVul Fix Pair: Insufficiently Protected Credentials in typescript
**Pair ID:** 4317_3
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4317_3`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```typescript
Lines 9-49 of the vulnerable file.

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import type {
  ConnectionOptions,
  Transport,
  Deferred,
  Server,
} from "./nats-base-client.ts";
import {
  ErrorCode,
  NatsError,
  render,
  deferred,
  delay,
} from "./nats-base-client.ts";

const VERSION = "1.0.0-110";
const LANG = "nats.ws";

export class WsTransport implements Transport {
  version: string = VERSION;
  lang: string = LANG;
  closeError?: Error;
  connected = false;
  private done = false;
  // @ts-ignore
  private socket: WebSocket;
  private options!: ConnectionOptions;
  socketClosed = false;
  encrypted = false;

  yields: Uint8Array[] = [];
  signal: Deferred<void> = deferred<void>();
  private closedNotification: Deferred<void | Error> = deferred();

  constructor() {
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
   delay,
 } from "./nats-base-client.ts";
 
-const VERSION = "1.0.0-110";
+const VERSION = "1.0.0-111";
 const LANG = "nats.ws";
 
 export class WsTransport implements Transport {
```
