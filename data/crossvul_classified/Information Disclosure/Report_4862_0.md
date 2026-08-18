# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 4862_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4862_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 60-100 of the vulnerable file.

DeclareSetting(uint64, RealBetaVersion);
DeclareSetting(QByteArray, BetaPrivateKey);

DeclareSetting(bool, TestMode);
DeclareSetting(QString, LoggedPhoneNumber);
DeclareSetting(bool, AutoStart);
DeclareSetting(bool, StartMinimized);
DeclareSetting(bool, StartInTray);
DeclareSetting(bool, SendToMenu);
DeclareSetting(bool, UseExternalVideoPlayer);
enum LaunchMode {
	LaunchModeNormal = 0,
	LaunchModeAutoStart,
	LaunchModeFixPrevious,
	LaunchModeCleanup,
};
DeclareReadSetting(LaunchMode, LaunchMode);
DeclareSetting(QString, WorkingDir);
inline void cForceWorkingDir(const QString &newDir) {
	cSetWorkingDir(newDir);
	if (!gWorkingDir.isEmpty()) QDir().mkpath(gWorkingDir);
}
DeclareReadSetting(QString, ExeName);
DeclareReadSetting(QString, ExeDir);
DeclareSetting(QString, DialogLastPath);
DeclareSetting(QString, DialogHelperPath);
inline const QString &cDialogHelperPathFinal() {
	return cDialogHelperPath().isEmpty() ? cExeDir() : cDialogHelperPath();
}
DeclareSetting(bool, CtrlEnter);

DeclareSetting(bool, AutoUpdate);

struct TWindowPos {
	TWindowPos() = default;

	int32 moncrc = 0;
	int maximized = 0;
	int x = 0;
	int y = 0;
	int w = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,7 +77,12 @@
 DeclareSetting(QString, WorkingDir);
 inline void cForceWorkingDir(const QString &newDir) {
 	cSetWorkingDir(newDir);
-	if (!gWorkingDir.isEmpty()) QDir().mkpath(gWorkingDir);
+	if (!gWorkingDir.isEmpty()) {
+		QDir().mkpath(gWorkingDir);
+		QFile::setPermissions(gWorkingDir,
+			QFileDevice::ReadUser | QFileDevice::WriteUser | QFileDevice::ExeUser);
+	}
+
 }
 DeclareReadSetting(QString, ExeName);
 DeclareReadSetting(QString, ExeDir);
```
