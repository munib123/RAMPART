# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in php
**Pair ID:** 3259_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3259_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```php
Lines 136-176 of the vulnerable file.

\
test1300 test1301 test1302 test1303 test1304 test1305 test1306 test1307 \
test1308 test1309 test1310 test1311 test1312 test1313 test1314 test1315 \
test1316 test1317 test1318 test1319 test1320 test1321 test1322          \
         test1325 test1326 test1327 test1328 test1329 test1330 test1331 \
test1332 test1333 test1334 test1335 test1336 test1337 test1338 test1339 \
test1340 test1341 test1342 test1343 test1344 test1345 test1346 test1347 \
test1348 test1349 test1350 test1351 test1352 test1353 test1354 test1355 \
test1356 test1357 test1358 test1359 test1360 test1361 test1362 test1363 \
test1364 test1365 test1366 test1367 test1368 test1369 test1370 test1371 \
test1372 test1373 test1374 test1375 test1376 test1377 test1378 test1379 \
test1380 test1381 test1382 test1383 test1384 test1385 test1386 test1387 \
test1388 test1389 test1390 test1391 test1392 test1393 test1394 test1395 \
test1396 test1397 test1398 \
\
test1400 test1401 test1402 test1403 test1404 test1405 test1406 test1407 \
test1408 test1409 test1410 test1411 test1412 test1413 test1414 test1415 \
test1416 test1417 test1418 test1419 test1420 test1421 test1422 test1423 \
test1424 \
test1428 test1429 test1430 test1431 test1432 test1433 test1434 test1435 \
test1436 test1437 test1438 test1439 \
\
test1500 test1501 test1502 test1503 test1504 test1505 test1506 test1507 \
test1508 test1509 test1510 test1511 test1512 test1513 test1514 test1515 \
test1516 test1517 \
\
test1520 \
\
test1525 test1526 test1527 test1528 test1529 test1530 test1531 test1532 \
test1533 test1534 test1535 test1536 \
\
test1600 test1601 test1602 test1603 test1604 test1605 \
\
test1700 test1701 test1702 \
\
test1800 test1801 \
\
test1900 test1901 test1902 test1903 \
\
test2000 test2001 test2002 test2003 test2004 test2005 test2006 test2007 \
test2008 test2009 test2010 test2011 test2012 test2013 test2014 test2015 \
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -153,7 +153,7 @@
 test1416 test1417 test1418 test1419 test1420 test1421 test1422 test1423 \
 test1424 \
 test1428 test1429 test1430 test1431 test1432 test1433 test1434 test1435 \
-test1436 test1437 test1438 test1439 \
+test1436 test1437 test1438 test1439 test1440 test1441 \
 \
 test1500 test1501 test1502 test1503 test1504 test1505 test1506 test1507 \
 test1508 test1509 test1510 test1511 test1512 test1513 test1514 test1515 \
```
