# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in csharp
**Pair ID:** 3685_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3685_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```csharp
Lines 25-57 of the vulnerable file.

// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

namespace System.Web
{
	class HttpForbiddenHandler : IHttpHandler
	{
		public void ProcessRequest (HttpContext context)
		{
			HttpRequest req = context != null ? context.Request : null;
			string path = req != null ? req.Path : null;
			string description = "The type of page you have requested is not served because it has been explicitly forbidden. The extension '" +
				(path == null ? String.Empty : VirtualPathUtility.GetExtension (path)) +
				"' may be incorrect. Please review the URL below and make sure that it is spelled correctly.";
				
			throw new HttpException (403,
						 "This type of page is not served.",
						 req != null ? req.Path : null,
						 description);
		}

		public bool IsReusable
		{
			get {
				return true;
			}
		}
	}
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,7 +42,7 @@
 				
 			throw new HttpException (403,
 						 "This type of page is not served.",
-						 req != null ? req.Path : null,
+						 req != null ? HttpUtility.HtmlEncode (req.Path) : null,
 						 description);
 		}
 
```
