# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 5719_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5719_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */
#ifndef _PASSENGER_SERVER_INSTANCE_DIR_H_
#define _PASSENGER_SERVER_INSTANCE_DIR_H_

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <oxt/backtrace.hpp>

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <cstdlib>
#include <cstring>
#include <string>

#include <Constants.h>
#include <Exceptions.h>
#include <Utils.h>
#include <Utils/StrIntUtils.h>

namespace Passenger {

using namespace std;
using namespace boost;

class ServerInstanceDir: public noncopyable {
public:
	class Generation: public noncopyable {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,7 @@
 #include <oxt/backtrace.hpp>
 
 #include <sys/types.h>
+#include <sys/stat.h>
 #include <dirent.h>
 #include <unistd.h>
 #include <pwd.h>
@@ -214,7 +215,33 @@
 		 * rights though, because we want admin tools to be able to list the available
 		 * generations no matter what user they're running as.
 		 */
-		makeDirTree(path, "u=rwx,g=rx,o=rx");
+		if (owner) {
+			switch (getFileType(path)) {
+			case FT_NONEXISTANT:
+				createDirectory(path);
+				break;
+			case FT_DIRECTORY:
+				removeDirTree(path);
+				createDirectory(path);
+				break;
+			default:
+				throw RuntimeException("'" + path + "' already exists, and is not a directory");
+			}
+		} else if (getFileType(path) != FT_DIRECTORY) {
+			throw RuntimeException("Server instance directory '" + path +
+				"' does not exist");
+		}
+	}
+
+	void createDirectory(const string &path) const {
+		// We do not use makeDirTree() here. If an attacker creates a directory
+		// just before we do, then we want to abort because we want the directory
+		// to have specific permissions.
+		if (mkdir(path.c_str(), parseModeString("u=rwx,g=rx,o=rx")) == -1) {
+			int e = errno;
+			throw FileSystemException("Cannot create server instance directory '" +
+				path + "'", e, path);
+		}
 	}
 	
 	bool isDirectory(const string &dir, struct dirent *entry) const {
```
