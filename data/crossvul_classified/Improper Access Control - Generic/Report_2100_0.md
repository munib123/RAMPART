# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 2100_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2100_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 185-220 of the vulnerable file.

     *
     */
    public static class HeapDump {
        private final AccessControlled owner;
        private final VirtualChannel channel;

        public HeapDump(AccessControlled owner, VirtualChannel channel) {
            this.owner = owner;
            this.channel = channel;
        }

        /**
         * Obtains the heap dump.
         */
        public void doIndex(StaplerResponse rsp) throws IOException {
            rsp.sendRedirect("heapdump.hprof");
        }

        @WebMethod(name="heapdump.hprof")
        public void doHeapDump(StaplerRequest req, StaplerResponse rsp) throws IOException, InterruptedException {
            owner.checkPermission(Jenkins.ADMINISTER);
            rsp.setContentType("application/octet-stream");

            FilePath dump = obtain();
            try {
                dump.copyTo(rsp.getCompressedOutputStream(req));
            } finally {
                dump.delete();
            }
        }

        public FilePath obtain() throws IOException, InterruptedException {
            return RemotingDiagnostics.getHeapDump(channel);
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -202,7 +202,7 @@
 
         @WebMethod(name="heapdump.hprof")
         public void doHeapDump(StaplerRequest req, StaplerResponse rsp) throws IOException, InterruptedException {
-            owner.checkPermission(Jenkins.ADMINISTER);
+            owner.checkPermission(Jenkins.RUN_SCRIPTS);
             rsp.setContentType("application/octet-stream");
 
             FilePath dump = obtain();
```
