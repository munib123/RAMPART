# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 3250_4
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3250_4`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 6-46 of the vulnerable file.

#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
from setuptools import setup

setup(
    name='security_monkey',
    version='0.8.0',
    long_description=__doc__,
    packages=['security_monkey'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'APScheduler==2.1.2',
        'Flask==0.10.1',
        'Flask-Login==0.2.10',
        'Flask-Mail==0.9.0',
        'Flask-Migrate==1.3.1',
        'Flask-Principal==0.4.0',
        'Flask-RESTful==0.3.3',
        'Flask-SQLAlchemy==1.0',
        'Flask-Script==0.6.3',
        'Flask-Security==1.7.4',
        'Flask-WTF==0.9.5',
        'Jinja2==2.8',
        'SQLAlchemy==0.9.2',
        'boto>=2.41.0',
        'ipaddr==2.1.11',
        'itsdangerous==0.23',
        'psycopg2==2.5.2',
        'bcrypt==2.0.0',
        'Sphinx==1.2.2',
        'gunicorn==18.0',
        'cryptography==1.3.2',
        'boto3>=1.4.2',
        'botocore>=1.4.81',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,25 +23,24 @@
     install_requires=[
         'APScheduler==2.1.2',
         'Flask==0.10.1',
-        'Flask-Login==0.2.10',
         'Flask-Mail==0.9.0',
         'Flask-Migrate==1.3.1',
         'Flask-Principal==0.4.0',
         'Flask-RESTful==0.3.3',
         'Flask-SQLAlchemy==1.0',
         'Flask-Script==0.6.3',
-        'Flask-Security==1.7.4',
-        'Flask-WTF==0.9.5',
+        # 'Flask-Security==1.7.4',
+        'Flask-Security-Fork==1.8.2',
         'Jinja2==2.8',
         'SQLAlchemy==0.9.2',
         'boto>=2.41.0',
         'ipaddr==2.1.11',
         'itsdangerous==0.23',
-        'psycopg2==2.5.2',
-        'bcrypt==2.0.0',
+        'psycopg2==2.6.2',
+        'bcrypt==3.1.2',
         'Sphinx==1.2.2',
         'gunicorn==18.0',
-        'cryptography==1.3.2',
+        'cryptography==1.7.1',
         'boto3>=1.4.2',
         'botocore>=1.4.81',
         'dpath==1.3.2',
```
