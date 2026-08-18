# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in shell
**Pair ID:** 1662_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1662_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```bash
Lines 14-54 of the vulnerable file.

#     * Neither the name of Intel Corporation nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
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
# copy a file to all hosts

trap "exit 1" SIGHUP SIGTERM SIGINT

# optional override of defaults
if [ -f /etc/sysconfig/opa/opafastfabric.conf ]
then
	. /etc/sysconfig/opa/opafastfabric.conf
fi

. /opt/opa/tools/opafastfabric.conf.def

. /opt/opa/tools/ff_funcs

temp=/tmp/opascpall$$
trap "rm -f $temp" 1 2 3 9 15

Usage_full()
{
	echo "Usage: opascpall [-p] [-r] [-f hostfile] [-h 'hosts'] [-u user] source_file ... dest_file" >&2
	echo "       opascpall -t [-p] [-f hostfile] [-h 'hosts'] [-u user] [source_dir [dest_dir]]" >&2
	echo "              or" >&2
	echo "       opascpall --help" >&2
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,9 @@
 # [ICS VERSION STRING: unknown]
 # copy a file to all hosts
 
-trap "exit 1" SIGHUP SIGTERM SIGINT
+temp="$(mktemp --tmpdir "opascpall.XXXXXX")"
+trap "rm -f $temp; exit 1" SIGHUP SIGTERM SIGINT
+trap "rm -f $temp" EXIT
 
 # optional override of defaults
 if [ -f /etc/sysconfig/opa/opafastfabric.conf ]
@@ -43,7 +45,7 @@
 
 . /opt/opa/tools/ff_funcs
 
-temp=/tmp/opascpall$$
+temp=`mktemp`
 trap "rm -f $temp" 1 2 3 9 15
 
 Usage_full()
```
