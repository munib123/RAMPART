# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in typescript
**Pair ID:** 1187_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1187_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```typescript
Lines 14-40 of the vulnerable file.

 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
import { partition, sortBy } from 'lodash';
import { translate } from '../../helpers/l10n';

const PROVIDED_TYPES = ['homepage', 'ci', 'issue', 'scm', 'scm_dev'];
type NameAndType = Pick<T.ProjectLink, 'name' | 'type'>;

export function isProvided(link: Pick<T.ProjectLink, 'type'>) {
  return PROVIDED_TYPES.includes(link.type);
}

export function orderLinks<T extends NameAndType>(links: T[]) {
  const [provided, unknown] = partition<T>(links, isProvided);
  return [
    ...sortBy(provided, link => PROVIDED_TYPES.indexOf(link.type)),
    ...sortBy(unknown, link => link.name!.toLowerCase())
  ];
}

export function getLinkName(link: NameAndType) {
  return isProvided(link) ? translate('project_links', link.type) : link.name;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,7 @@
   const [provided, unknown] = partition<T>(links, isProvided);
   return [
     ...sortBy(provided, link => PROVIDED_TYPES.indexOf(link.type)),
-    ...sortBy(unknown, link => link.name!.toLowerCase())
+    ...sortBy(unknown, link => link.name && link.name.toLowerCase())
   ];
 }
 
```
