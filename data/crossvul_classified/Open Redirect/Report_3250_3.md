# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 3250_3
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3250_3`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 8-32 of the vulnerable file.

#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

from flask_login import current_user, logout_user
from flask_restful import Resource


# End the Flask-Logins session
from security_monkey import rbac


class Logout(Resource):

    decorators = [rbac.exempt]

    def get(self):
        if not current_user.is_authenticated():
            return "Must be logged in to log out", 200

        logout_user()
        return "Logged Out", 200
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
     decorators = [rbac.exempt]
 
     def get(self):
-        if not current_user.is_authenticated():
+        if not current_user.is_authenticated:
             return "Must be logged in to log out", 200
 
         logout_user()
```
