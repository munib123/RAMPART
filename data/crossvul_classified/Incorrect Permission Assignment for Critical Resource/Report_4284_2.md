# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in c
**Pair ID:** 4284_2
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4284_2`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```c
Lines 11-51 of the vulnerable file.

 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _OPENSOLARIS_SYS_SID_H_
#define	_OPENSOLARIS_SYS_SID_H_

typedef struct ksiddomain {
	char	*kd_name;	/* Domain part of SID */
	uint_t	kd_len;
} ksiddomain_t;
typedef void	ksid_t;

static __inline ksiddomain_t *
ksid_lookupdomain(const char *domain)
{
	ksiddomain_t *kd;
	size_t len;

	len = strlen(domain) + 1;
	kd = kmem_alloc(sizeof (*kd), KM_SLEEP);
	kd->kd_len = (uint_t)len;
	kd->kd_name = kmem_alloc(len, KM_SLEEP);
	strcpy(kd->kd_name, domain);
	return (kd);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,8 @@
 
 #ifndef _OPENSOLARIS_SYS_SID_H_
 #define	_OPENSOLARIS_SYS_SID_H_
+#include <sys/idmap.h>
+#include <sys/kidmap.h>
 
 typedef struct ksiddomain {
 	char	*kd_name;	/* Domain part of SID */
```
