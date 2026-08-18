# CrossVul Fix Pair: Cryptographic Issues in cpp
**Pair ID:** 3579_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3579_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```cpp
Lines 699-739 of the vulnerable file.

		qmPositionalAudioPlugins.insert(d, settings_ptr->value(d, true).toBool());
	}
	settings_ptr->endGroup();

	settings_ptr->beginGroup(QLatin1String("overlay"));
	os.load(settings_ptr);
	settings_ptr->endGroup();
}

#undef SAVELOAD
#define SAVELOAD(var,name) if (var != def.var) settings_ptr->setValue(QLatin1String(name), var); else settings_ptr->remove(QLatin1String(name))
#define SAVEFLAG(var,name) if (var != def.var) settings_ptr->setValue(QLatin1String(name), static_cast<int>(var)); else settings_ptr->remove(QLatin1String(name))

void OverlaySettings::save() {
	save(g.qs);
}

void OverlaySettings::save(QSettings* settings_ptr) {
	OverlaySettings def;

	SAVELOAD(bEnable, "enable");

	SAVELOAD(osShow, "show");
	SAVELOAD(bAlwaysSelf, "alwaysself");
	SAVELOAD(uiActiveTime, "activetime");
	SAVELOAD(osSort, "sort");
	SAVELOAD(fX, "x");
	SAVELOAD(fY, "y");
	SAVELOAD(fZoom, "zoom");
	SAVELOAD(uiColumns, "columns");

	settings_ptr->beginReadArray(QLatin1String("states"));
	for (int i=0; i<4; ++i) {
		settings_ptr->setArrayIndex(i);
		SAVELOAD(qcUserName[i], "color");
		SAVELOAD(fUser[i], "opacity");
	}
	settings_ptr->endArray();

	SAVELOAD(qfUserName, "userfont");
	SAVELOAD(qfChannel, "channelfont");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -716,6 +716,17 @@
 void OverlaySettings::save(QSettings* settings_ptr) {
 	OverlaySettings def;
 
+	settings_ptr->setValue(QLatin1String("version"), QLatin1String(MUMTEXT(MUMBLE_VERSION_STRING)));
+	settings_ptr->sync();
+
+#if defined(Q_OS_WIN) || defined(Q_OS_MAC)
+	if (settings_ptr->format() == QSettings::IniFormat)
+#endif
+        {
+               QFile f(settings_ptr->fileName());
+               f.setPermissions(f.permissions() & ~(QFile::ReadGroup | QFile::WriteGroup | QFile::ExeGroup | QFile::ReadOther | QFile::WriteOther | QFile::ExeOther));
+        }
+
 	SAVELOAD(bEnable, "enable");
 
 	SAVELOAD(osShow, "show");
```
