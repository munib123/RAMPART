# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in shell
**Pair ID:** 1662_8
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1662_8`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```bash
Lines 21-63 of the vulnerable file.

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

# query the SM via opareport and generate a switches file listing all the
# Externally Managed SilverStorm switches found in the fabric.

# Enhancements: optionally, do not generate an switches file, but use an existing
# switches file; optionally, update NodeDesc values in an switches file using
# NodeDesc values found in a specified topology.xml file and fabric link
# information obtained via opareport -o links (live fabric or snapshot).


## Includes
trap "exit 1" SIGHUP SIGTERM SIGINT

# optional override of defaults
if [ -f /etc/sysconfig/opa/opafastfabric.conf ]
then
	. /etc/sysconfig/opa/opafastfabric.conf
fi

. /opt/opa/tools/opafastfabric.conf.def

TOOLSDIR=${TOOLSDIR:-/opt/opa/tools}
BINDIR=${BINDIR:-/usr/sbin}

. $TOOLSDIR/ff_funcs

## Defines:
OPAEXPAND_FILE="$BINDIR/opaexpandfile"
OPA_REPORT="$BINDIR/opareport"
OPASAQUERY="$BINDIR/opasaquery"
XML_EXTRACT="$BINDIR/opaxmlextract"
GEN_OPASWITCHES_HELPER="$TOOLSDIR/opagenswitcheshelper"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,9 +38,6 @@
 # NodeDesc values found in a specified topology.xml file and fabric link
 # information obtained via opareport -o links (live fabric or snapshot).
 
-
-## Includes
-trap "exit 1" SIGHUP SIGTERM SIGINT
 
 # optional override of defaults
 if [ -f /etc/sysconfig/opa/opafastfabric.conf ]
@@ -160,6 +157,9 @@
 	fi
 }	# End of clean_files()
 
+trap 'clean_files; exit 1' SIGINT SIGHUP SIGTERM 
+trap clean_files EXIT
+
 Usage_full()
 {
 	echo "Usage: opagenswitches [-t portsfile] [-p ports] [-R]" >&2
@@ -221,7 +221,6 @@
 	echo "for example:" >&2
 	echo "   opagenswitches" >&2
 	echo "   opagenswitches -T topology.0:0.xml" >&2
-	clean_files
 	exit 2
 }	# End of Usage()
 
```
