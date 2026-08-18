# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in cpp
**Pair ID:** 915_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `915_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```cpp
Lines 286-326 of the vulnerable file.

        if (!part) {
            dCDebug("Part is null(index: %d)", index);

            return false;
        }

        dCDebug("Try open device: %s, mode: %s", qPrintable(part.filePath()), currentMode == DDiskInfo::Read ? "Read" : "Write");

        if (Helper::isMounted(part.filePath())) {
            if (Helper::umountDevice(part.filePath())) {
                part.d->mountPoint.clear();
            } else {
                setErrorString(QObject::tr("\"%1\" is busy").arg(part.filePath()));

                return false;
            }
        }

        if (currentMode == DDiskInfo::Read) {
            const QString &executer = Helper::getPartcloneExecuter(part);
            process->start(QStringLiteral("%1 -s %2 -o - -c -z %3 -L /tmp/partclone.log").arg(executer).arg(part.filePath()).arg(Global::bufferSize), QIODevice::ReadOnly);
        } else {
            process->start(QStringLiteral("partclone.restore -s - -o %2 -z %3 -L /tmp/partclone.log").arg(part.filePath()).arg(Global::bufferSize));
        }

        break;
    }
    case DDiskInfo::JsonInfo: {
        process->deleteLater();
        process = 0;
        buffer.setData(q->toJson());
        break;
    }
    default:
        return false;
    }

    if (process) {
        if (!process->waitForStarted()) {
            setErrorString(QObject::tr("Failed to start \"%1 %2\", error: %3").arg(process->program()).arg(process->arguments().join(" ")).arg(process->errorString()));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -303,9 +303,9 @@
 
         if (currentMode == DDiskInfo::Read) {
             const QString &executer = Helper::getPartcloneExecuter(part);
-            process->start(QStringLiteral("%1 -s %2 -o - -c -z %3 -L /tmp/partclone.log").arg(executer).arg(part.filePath()).arg(Global::bufferSize), QIODevice::ReadOnly);
+            process->start(QStringLiteral("%1 -s %2 -o - -c -z %3 -L /var/log/partclone.log").arg(executer).arg(part.filePath()).arg(Global::bufferSize), QIODevice::ReadOnly);
         } else {
-            process->start(QStringLiteral("partclone.restore -s - -o %2 -z %3 -L /tmp/partclone.log").arg(part.filePath()).arg(Global::bufferSize));
+            process->start(QStringLiteral("partclone.restore -s - -o %2 -z %3 -L /var/log/partclone.log").arg(part.filePath()).arg(Global::bufferSize));
         }
 
         break;
```
