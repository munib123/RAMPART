# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in cpp
**Pair ID:** 915_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `915_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```cpp
Lines 83-123 of the vulnerable file.


    if (Global::debugLevel > 1)
        dCDebug("Exec: \"%s\", timeout: %d", qPrintable(command), timeout);

    process->start(command, mode);
    process->waitForStarted();

    if (process->error() != QProcess::UnknownError) {
        dCError(process->errorString());

        return -1;
    }

    if (process->state() == QProcess::Running) {
        loop.exec();
    }

    if (process->state() != QProcess::NotRunning) {
        dCDebug("The \"%s\" timeout, timeout: %d", qPrintable(command), timeout);

        if (QFile::exists(QString("/proc/%1").arg(process->pid()))) {
            process->terminate();
            process->waitForFinished();
        } else {
            dCDebug("The \"%s\" is quit, but the QProcess object state is not NotRunning");
        }
    }

    m_processStandardOutput.append(process->readAllStandardOutput());
    m_processStandardError.append(process->readAllStandardError());

    if (Global::debugLevel > 1) {
        dCDebug("Done: \"%s\", exit code: %d", qPrintable(command), process->exitCode());

        if (process->exitCode() != 0) {
            dCError("error: \"%s\"\nstdout: \"%s\"", qPrintable(m_processStandardError), qPrintable(m_processStandardOutput));
        }
    }

    return process->exitCode();
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,6 +100,8 @@
     if (process->state() != QProcess::NotRunning) {
         dCDebug("The \"%s\" timeout, timeout: %d", qPrintable(command), timeout);
 
+        // QT Bug，某种情况下(未知) QProcess::state 返回的状态有误，导致进程已退出却未能正确获取到其当前状态
+        // 因此,额外通过系统文件判断进程是否还存在
         if (QFile::exists(QString("/proc/%1").arg(process->pid()))) {
             process->terminate();
             process->waitForFinished();
@@ -331,7 +333,7 @@
 
         return true;
     } else {
-        process.start(QString("%1 -s %2 -c -q -C -L /tmp/partclone.log").arg(getPartcloneExecuter(DDevicePartInfo(partDevice))).arg(partDevice));
+        process.start(QString("%1 -s %2 -c -q -C -L /var/log/partclone.log").arg(getPartcloneExecuter(DDevicePartInfo(partDevice))).arg(partDevice));
         process.setStandardOutputFile("/dev/null");
         process.setReadChannel(QProcess::StandardError);
         process.waitForStarted();
@@ -501,9 +503,9 @@
         return mount_point;
 
     mount_point = "%1/.%2/mount/%3";
-    const QStringList &tmp_paths = QStandardPaths::standardLocations(QStandardPaths::TempLocation);
-
-    mount_point = mount_point.arg(tmp_paths.isEmpty() ? "/tmp" : tmp_paths.first()).arg(qApp->applicationName()).arg(name);
+    const QStringList &tmp_paths = QStandardPaths::standardLocations(QStandardPaths::RuntimeLocation);
+
+    mount_point = mount_point.arg(tmp_paths.isEmpty() ? "/run/user/0" : tmp_paths.first()).arg(qApp->applicationName()).arg(name);
 
     if (!QDir::current().mkpath(mount_point)) {
         dCError("mkpath \"%s\" failed", qPrintable(mount_point));
```
