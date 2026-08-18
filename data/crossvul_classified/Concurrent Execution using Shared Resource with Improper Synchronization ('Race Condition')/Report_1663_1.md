# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in shell
**Pair ID:** 1663_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1663_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```bash
Lines 13-53 of the vulnerable file.

#       documentation and/or other materials provided with the distribution.
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

TEMP=/tmp/smgen$$
trap "rm -f $TEMP; exit 1" SIGHUP SIGTERM SIGINT

Usage()
{
	echo "Usage: config_generate [-e] dest_file" >&2
	echo "      -e  - generate file for embedded FM, default is to generate for host FM" >&2
	exit 2
}

if [ -f /opt/opa/fm_tools/config_convert -a -f /opt/opa/fm_tools/opafm_src.xml ]
then
	tooldir=/opt/opa/fm_tools
elif [ ! -f /etc/sysconfig/opa/opafm.info || ! -f /etc/sysconfig/opa/qlogic_fm.info ]
then
	echo "config_generate: IFS FM not installed" >&2
	exit 1
else
	if [ -f /etc/sysconfig/opa/qlogic_fm.info ]
        then
                cp -f /etc/sysconfig/opa/qlogic_fm.info /etc/sysconfig/opa/opafm.info
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,8 +30,9 @@
 
 # [ICS VERSION STRING: unknown]
 
-TEMP=/tmp/smgen$$
+TEMP=`mktemp`
 trap "rm -f $TEMP; exit 1" SIGHUP SIGTERM SIGINT
+trap "rm -f $TEMP" EXIT
 
 Usage()
 {
```
