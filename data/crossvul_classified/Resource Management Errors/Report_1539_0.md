# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 1539_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1539_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 15-55 of the vulnerable file.

 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.         *
 ***************************************************************************/

#include "corebasichandler.h"

#include "util.h"
#include "logger.h"

CoreBasicHandler::CoreBasicHandler(CoreNetwork *parent)
    : BasicHandler(parent),
    _network(parent)
{
    connect(this, SIGNAL(displayMsg(Message::Type, BufferInfo::Type, const QString &, const QString &, const QString &, Message::Flags)),
        network(), SLOT(displayMsg(Message::Type, BufferInfo::Type, const QString &, const QString &, const QString &, Message::Flags)));

    connect(this, SIGNAL(putCmd(QString, const QList<QByteArray> &, const QByteArray &)),
        network(), SLOT(putCmd(QString, const QList<QByteArray> &, const QByteArray &)));

    connect(this, SIGNAL(putRawLine(const QByteArray &)),
        network(), SLOT(putRawLine(const QByteArray &)));
}


QString CoreBasicHandler::serverDecode(const QByteArray &string)
{
    return network()->serverDecode(string);
}


QStringList CoreBasicHandler::serverDecode(const QList<QByteArray> &stringlist)
{
    QStringList list;
    foreach(QByteArray s, stringlist) list << network()->serverDecode(s);
    return list;
}


QString CoreBasicHandler::channelDecode(const QString &bufferName, const QByteArray &string)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,9 @@
 
     connect(this, SIGNAL(putCmd(QString, const QList<QByteArray> &, const QByteArray &)),
         network(), SLOT(putCmd(QString, const QList<QByteArray> &, const QByteArray &)));
+
+    connect(this, SIGNAL(putCmd(QString, const QList<QList<QByteArray>> &, const QByteArray &)),
+        network(), SLOT(putCmd(QString, const QList<QList<QByteArray>> &, const QByteArray &)));
 
     connect(this, SIGNAL(putRawLine(const QByteArray &)),
         network(), SLOT(putRawLine(const QByteArray &)));
```
