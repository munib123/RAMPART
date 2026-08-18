# CrossVul Fix Pair: Inadequate Encryption Strength in c
**Pair ID:** 3963_1
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3963_1`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```c
Lines 23-47 of the vulnerable file.

 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __SECURE_H__
#define __SECURE_H__

struct image_info;


#define AT91_SECURE_MAGIC	0x0000aa55

/* the size of this structure MUST be equal to the size of an AES block */
typedef struct at91_secure_header {
	unsigned int		magic;
	unsigned int		file_size;
	unsigned int		reserved[2];
} at91_secure_header_t;


int secure_decrypt(void *data, unsigned int data_length, int is_signed);
int secure_check(void *data);

#endif /* #ifdef __SECURE_H__ */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,8 +40,6 @@
 	unsigned int		reserved[2];
 } at91_secure_header_t;
 
-
-int secure_decrypt(void *data, unsigned int data_length, int is_signed);
 int secure_check(void *data);
 
 #endif /* #ifdef __SECURE_H__ */
```
