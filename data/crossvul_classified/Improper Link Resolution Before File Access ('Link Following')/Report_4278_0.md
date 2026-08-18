# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in cpp
**Pair ID:** 4278_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4278_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```cpp
Lines 492-546 of the vulnerable file.

    }
    e->setProperty("isExecutable", mode & (S_IXUSR | S_IXGRP | S_IXOTH));

    e->compressedSizeIsSet = false;
    e->setProperty("size", (qlonglong)archive_entry_size(aentry));
    e->setProperty("isDirectory", S_ISDIR(archive_entry_mode(aentry)));

    if (archive_entry_symlink(aentry)) {
        e->setProperty("link", QLatin1String( archive_entry_symlink(aentry) ));
    }

    auto time = static_cast<uint>(archive_entry_mtime(aentry));
    e->setProperty("timestamp", QDateTime::fromSecsSinceEpoch(time));

    emit entry(e);
    m_emittedEntries << e;
}

int LibarchivePlugin::extractionFlags() const
{
    int result = ARCHIVE_EXTRACT_TIME;
    result |= ARCHIVE_EXTRACT_SECURE_NODOTDOT;

    // TODO: Don't use arksettings here
    /*if ( ArkSettings::preservePerms() )
    {
        result &= ARCHIVE_EXTRACT_PERM;
    }

    if ( !ArkSettings::extractOverwrite() )
    {
        result &= ARCHIVE_EXTRACT_NO_OVERWRITE;
    }*/

    return result;
}

void LibarchivePlugin::copyData(const QString& filename, struct archive *dest, bool partialprogress)
{
    char buff[10240];
    QFile file(filename);

    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    auto readBytes = file.read(buff, sizeof(buff));
    while (readBytes > 0 && !QThread::currentThread()->isInterruptionRequested()) {
        archive_write_data(dest, buff, static_cast<size_t>(readBytes));
        if (archive_errno(dest) != ARCHIVE_OK) {
            qCCritical(ARK) << "Error while writing" << filename << ":" << archive_error_string(dest)
                            << "(error no =" << archive_errno(dest) << ')';
            return;
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -509,21 +509,9 @@
 
 int LibarchivePlugin::extractionFlags() const
 {
-    int result = ARCHIVE_EXTRACT_TIME;
-    result |= ARCHIVE_EXTRACT_SECURE_NODOTDOT;
-
-    // TODO: Don't use arksettings here
-    /*if ( ArkSettings::preservePerms() )
-    {
-        result &= ARCHIVE_EXTRACT_PERM;
-    }
-
-    if ( !ArkSettings::extractOverwrite() )
-    {
-        result &= ARCHIVE_EXTRACT_NO_OVERWRITE;
-    }*/
-
-    return result;
+    return ARCHIVE_EXTRACT_TIME
+           | ARCHIVE_EXTRACT_SECURE_NODOTDOT
+           | ARCHIVE_EXTRACT_SECURE_SYMLINKS;
 }
 
 void LibarchivePlugin::copyData(const QString& filename, struct archive *dest, bool partialprogress)
```
