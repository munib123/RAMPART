# CrossVul Fix Pair: Improper Access Control in java
**Pair ID:** 873_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `873_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```java
Lines 29-69 of the vulnerable file.

    private DynmapCore core;
    private byte[] blankpng;
    private long blankpnghash = 0x12345678;
    
    public MapStorageResourceHandler() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BufferedImage blank = new BufferedImage(128, 128, BufferedImage.TYPE_INT_ARGB);
        try {
            ImageIO.write(blank, "png", baos);
            blankpng = baos.toByteArray();
        } catch (IOException e) {
        }
        
    }
    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String path = baseRequest.getPathInfo();
        int soff = 0, eoff;
        // We're handling this request
        baseRequest.setHandled(true);

        if (path.charAt(0) == '/') soff = 1;
        eoff = path.indexOf('/', soff);
        if (soff < 0) {
            response.sendError(HttpStatus.NOT_FOUND_404);
            return;
        }
        String world = path.substring(soff, eoff);
        String uri = path.substring(eoff+1);
        // If faces directory, handle faces
        if (world.equals("faces")) {
            handleFace(response, uri);
            return;
        }
        // If markers directory, handle markers
        if (world.equals("_markers_")) {
            handleMarkers(response, uri);
            return;
        }

        DynmapWorld w = null;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,11 @@
         int soff = 0, eoff;
         // We're handling this request
         baseRequest.setHandled(true);
-
+        if(core.getLoginRequired()
+            && request.getSession(true).getAttribute(LoginServlet.USERID_ATTRIB) == null){
+            response.sendError(HttpStatus.UNAUTHORIZED_401);
+            return;
+        }
         if (path.charAt(0) == '/') soff = 1;
         eoff = path.indexOf('/', soff);
         if (soff < 0) {
```
