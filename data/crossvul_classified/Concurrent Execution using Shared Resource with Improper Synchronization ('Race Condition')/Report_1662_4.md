# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in shell
**Pair ID:** 1662_4
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1662_4`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```bash
Lines 19-59 of the vulnerable file.

# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# END_ICS_COPYRIGHT8   ****************************************

# [ICS VERSION STRING: unknown]

# Run opareports and pipe output to opaxmlextract to extract
#  links with excessive errors

TOOLSDIR=${TOOLSDIR:-/opt/opa/tools}
BINDIR=${BINDIR:-/usr/sbin}

tempfile=/tmp/opaextractbadlinks$$
trap "rm -f $tempfile; exit 1" SIGHUP SIGTERM SIGINT

Usage_full()
{
	echo "Usage: opaextractbadlinks [opareport options]" >&2
	echo "              or" >&2
	echo "       opaextractbadlinks --help" >&2
	echo "   --help - produce full help text" >&2
	echo "   opareport options - options will be passed to opareport." >&2
	echo "for example:" >&2
	echo "   opaextractbadlinks" >&2
	echo "   opaextractbadlinks -h 1 -p 2" >&2
	exit 0
}

Usage()
{
	echo "Usage: opaextractbadlinks" >&2
	echo "              or" >&2
	echo "       opaextractbadlinks --help" >&2
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,8 +36,9 @@
 TOOLSDIR=${TOOLSDIR:-/opt/opa/tools}
 BINDIR=${BINDIR:-/usr/sbin}
 
-tempfile=/tmp/opaextractbadlinks$$
+tempfile=`mktemp`
 trap "rm -f $tempfile; exit 1" SIGHUP SIGTERM SIGINT
+trap "rm -f $tempfile" EXIT
 
 Usage_full()
 {
```
