# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 3389_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3389_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 310-350 of the vulnerable file.

    }
    m_names[1]=libstoff::getString(text);
  }
  if (zone.isCompatibleWith(0x12,0x22, 0x101)) {
    int nCount=int(input->readULong(2));
    if (nCount>0 && zone.isCompatibleWith(0x28)) {
      for (int i=0; i<nCount; ++i) {
        if (input->tell()>=zone.getRecordLastPosition()) {
          STOFF_DEBUG_MSG(("StarWriterStruct::DatabaseName::read: can not read a DBData\n"));
          f << "###";
          break;
        }
        Data data;
        if (!zone.readString(text)) {
          STOFF_DEBUG_MSG(("StarWriterStruct::DatabaseName::read: can not read a table name string\n"));
          f << "###dbDataName";
          break;
        }
        data.m_name=libstoff::getString(text);
        int positions[2];
        for (int j=0; j<2; ++j) positions[i]=int(input->readULong(4));
        data.m_selection=STOFFVec2i(positions[0],positions[1]);
        m_dataList.push_back(data);
      }
    }
  }
  f << *this;
  ascFile.addPos(pos);
  ascFile.addNote(f.str().c_str());
  zone.closeSWRecord(type, "StarDatabaseName");
  return true;
}

std::ostream &operator<<(std::ostream &o, DatabaseName const &dbase)
{
  for (int i=0; i<2; ++i) {
    if (dbase.m_names[i].empty()) continue;
    char const *(wh[])= {"name[database]", "name[table]"};
    o << wh[i] << "=" << dbase.m_names[i].cstr() << ",";
  }
  if (!dbase.m_sql.empty()) o << "sql=" << dbase.m_sql.cstr() << ",";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -327,7 +327,7 @@
         }
         data.m_name=libstoff::getString(text);
         int positions[2];
-        for (int j=0; j<2; ++j) positions[i]=int(input->readULong(4));
+        for (int j=0; j<2; ++j) positions[j]=int(input->readULong(4));
         data.m_selection=STOFFVec2i(positions[0],positions[1]);
         m_dataList.push_back(data);
       }
```
