# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2295_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2295_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 18-58 of the vulnerable file.

 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
	if (nbytes <= sizeof(elfhdr))
		return 0;

	u.l = 1;
	(void)memcpy(&elfhdr, buf, sizeof elfhdr);
	swap = (u.c[sizeof(int32_t) - 1] + 1) != elfhdr.e_ident[EI_DATA];

	type = elf_getu16(swap, elfhdr.e_type);
	switch (type) {
#ifdef ELFCORE
	case ET_CORE:
		flags |= FLAGS_IS_CORE;
		if (dophn_core(ms, clazz, swap, fd,
		    (off_t)elf_getu(swap, elfhdr.e_phoff),
		    elf_getu16(swap, elfhdr.e_phnum), 
		    (size_t)elf_getu16(swap, elfhdr.e_phentsize),
		    fsize, &flags) == -1)
			return -1;
		break;
#endif
	case ET_EXEC:
	case ET_DYN:
		if (dophn_exec(ms, clazz, swap, fd,
		    (off_t)elf_getu(swap, elfhdr.e_phoff),
		    elf_getu16(swap, elfhdr.e_phnum), 
		    (size_t)elf_getu16(swap, elfhdr.e_phentsize),
		    fsize, &flags, elf_getu16(swap, elfhdr.e_shnum))
		    == -1)
			return -1;
		/*FALLTHROUGH*/
	case ET_REL:
		if (doshn(ms, clazz, swap, fd,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,10 +35,12 @@
 	switch (type) {
 #ifdef ELFCORE
 	case ET_CORE:
+		phnum = elf_getu16(swap, elfhdr.e_phnum);
+		if (phnum > MAX_PHNUM)
+			return toomany(ms, "program", phnum);
 		flags |= FLAGS_IS_CORE;
 		if (dophn_core(ms, clazz, swap, fd,
-		    (off_t)elf_getu(swap, elfhdr.e_phoff),
-		    elf_getu16(swap, elfhdr.e_phnum), 
+		    (off_t)elf_getu(swap, elfhdr.e_phoff), phnum,
 		    (size_t)elf_getu16(swap, elfhdr.e_phentsize),
 		    fsize, &flags) == -1)
 			return -1;
@@ -46,18 +48,24 @@
 #endif
 	case ET_EXEC:
 	case ET_DYN:
+		phnum = elf_getu16(swap, elfhdr.e_phnum);
+		if (phnum > MAX_PHNUM)
+			return toomany(ms, "program", phnum);
+		shnum = elf_getu16(swap, elfhdr.e_shnum);
+		if (shnum > MAX_SHNUM)
+			return toomany(ms, "section", shnum);
 		if (dophn_exec(ms, clazz, swap, fd,
-		    (off_t)elf_getu(swap, elfhdr.e_phoff),
-		    elf_getu16(swap, elfhdr.e_phnum), 
+		    (off_t)elf_getu(swap, elfhdr.e_phoff), phnum,
 		    (size_t)elf_getu16(swap, elfhdr.e_phentsize),
-		    fsize, &flags, elf_getu16(swap, elfhdr.e_shnum))
-		    == -1)
+		    fsize, &flags, shnum) == -1)
 			return -1;
 		/*FALLTHROUGH*/
 	case ET_REL:
+		shnum = elf_getu16(swap, elfhdr.e_shnum);
+		if (shnum > MAX_SHNUM)
+			return toomany(ms, "section", shnum);
 		if (doshn(ms, clazz, swap, fd,
-		    (off_t)elf_getu(swap, elfhdr.e_shoff),
-		    elf_getu16(swap, elfhdr.e_shnum),
+		    (off_t)elf_getu(swap, elfhdr.e_shoff), shnum,
 		    (size_t)elf_getu16(swap, elfhdr.e_shentsize),
 		    fsize, &flags, elf_getu16(swap, elfhdr.e_machine),
 		    (int)elf_getu16(swap, elfhdr.e_shstrndx)) == -1)
```
