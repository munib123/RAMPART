# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in cpp
**Pair ID:** 915_3
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `915_3`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```cpp
Lines 38-79 of the vulnerable file.

            if (Helper::resetPartUUID(part_info)) {
                QThread::sleep(1);
                part_info.refresh();

                qDebug() << part_old_uuid << part_info.uuid();
            } else {
                dCWarning("Failed to reset uuid");
            }
        }
    }

    bool device_is_mounted = Helper::isMounted(partDevice);
    const QString &mount_root = Helper::temporaryMountDevice(partDevice, QFileInfo(partDevice).fileName());

    if (mount_root.isEmpty()) {
        m_lastErrorString = QObject::tr("Failed to mount partition \"%1\"").arg(partDevice);
        goto failed;
    }

    {
        const QStringList &tmp_paths = QStandardPaths::standardLocations(QStandardPaths::TempLocation);
        const QString tmp_dir = (tmp_paths.isEmpty() ? "/tmp" : tmp_paths.first()) + "/.deepin-clone";

        if (!QDir::current().mkpath(tmp_dir)) {
            dCError("mkpath \"%s\" failed", qPrintable(tmp_dir));
            goto failed;
        }

        const QString &repo_path = tmp_dir + "/repo.iso";

        if (!QFile::exists(repo_path)
                && !QFile::copy(QString(":/repo_%1.iso").arg(HOST_ARCH), repo_path)) {
            dCError("copy file failed, new name: %s", qPrintable(repo_path));
            goto failed;
        }

        bool ok = false;

        const QString &repo_mount_point = mount_root + "/deepin-clone";
        QFile file_boot_fix(mount_root + "/boot_fix.sh");

        do {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,8 +55,7 @@
     }
 
     {
-        const QStringList &tmp_paths = QStandardPaths::standardLocations(QStandardPaths::TempLocation);
-        const QString tmp_dir = (tmp_paths.isEmpty() ? "/tmp" : tmp_paths.first()) + "/.deepin-clone";
+        const QString tmp_dir = "/var/cache/deepin-clone";
 
         if (!QDir::current().mkpath(tmp_dir)) {
             dCError("mkpath \"%s\" failed", qPrintable(tmp_dir));
```
