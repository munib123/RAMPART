# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 1920_6
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1920_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 2055-2098 of the vulnerable file.

// leboncoin
router.get('/leboncoin/ad/:query', require('./routes/leboncoin/ad.js'));

// DHL
router.get('/dhl/:id', require('./routes/dhl/shipment-tracking'));

// Japanpost
router.get('/japanpost/:reqCode/:locale?', require('./routes/japanpost/index'));

// 中华人民共和国商务部
router.get('/mofcom/article/:suffix', require('./routes/mofcom/article'));

// 品玩
router.get('/pingwest/status', require('./routes/pingwest/status'));
router.get('/pingwest/tag/:tag/:type', require('./routes/pingwest/tag'));
router.get('/pingwest/user/:uid/:type?', require('./routes/pingwest/user'));

// Hanime
router.get('/hanime/video', require('./routes/hanime/video'));

// 篝火营地
router.get('/gouhuo/news/:category', require('./routes/gouhuo'));
router.get('/gouhuo/strategy', require('./routes/gouhuo/strategy'));

// Soul
router.get('/soul/:id', require('./routes/soul'));
router.get('/soul/posts/hot', require('./routes/soul/hot'));

// 单向空间
router.get('/owspace/read/:type?', require('./routes/owspace/read'));

// 天涯论坛
router.get('/tianya/index/:type', require('./routes/tianya/index'));
router.get('/tianya/user/:userid', require('./routes/tianya/user'));
router.get('/tianya/comments/:userid', require('./routes/tianya/comments'));

// eleme
router.get('/eleme/open/announce', require('./routes/eleme/open/announce'));
router.get('/eleme/open-be/announce', require('./routes/eleme/open-be/announce'));

// 美团开放平台
router.get('/meituan/open/announce', require('./routes/meituan/open/announce'));

// 微信开放社区
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2072,10 +2072,6 @@
 // Hanime
 router.get('/hanime/video', require('./routes/hanime/video'));
 
-// 篝火营地
-router.get('/gouhuo/news/:category', require('./routes/gouhuo'));
-router.get('/gouhuo/strategy', require('./routes/gouhuo/strategy'));
-
 // Soul
 router.get('/soul/:id', require('./routes/soul'));
 router.get('/soul/posts/hot', require('./routes/soul/hot'));
@@ -2141,9 +2137,6 @@
 // 前端艺术家每日整理&&飞冰早报
 router.get('/jskou/:type?', require('./routes/jskou/index'));
 
-// 前端
-router.get('/front-end-rss', require('./routes/frontend/index'));
-
 // 国家应急广播
 router.get('/cneb/yjxx', require('./routes/cneb/yjxx'));
 router.get('/cneb/guoneinews', require('./routes/cneb/guoneinews'));
@@ -2177,9 +2170,6 @@
 
 // 腾讯企鹅号
 router.get('/tencent/news/author/:mid', require('./routes/tencent/news/author'));
-
-// 腾讯柠檬精选
-router.get('/tencent/lemon', require('./routes/tencent/lemon/index'));
 
 // 奈菲影视
 router.get('/nfmovies/:id?', require('./routes/nfmovies/index'));
@@ -3056,7 +3046,6 @@
 // 网易新闻
 router.get('/netease/news/rank/:category?/:type?/:time?', require('./routes/netease/news/rank'));
 router.get('/netease/news/special/:type?', require('./routes/netease/news/special'));
-router.get('/netease/news/data', require('./routes/netease/news/data'));
 
 // 网易 - 网易号
 router.get('/netease/dy/:id', require('./routes/netease/dy'));
@@ -3168,9 +3157,6 @@
 
 // 猎趣TV
 router.get('/liequtv/room/:id', require('./routes/liequtv/room'));
-
-// 黑白直播
-router.get('/heibaizhibo/room/:id', require('./routes/heibaizhibo/room'));
 
 // Behance
 router.get('/behance/:user/:type?', require('./routes/behance/index'));
```
