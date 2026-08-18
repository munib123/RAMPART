# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3083_5
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3083_5`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 370-410 of the vulnerable file.

                0, this.nodeCount);

        restartHost(owner);

        this.host.waitForReplicatedFactoryChildServiceConvergence(
                this.host.getNodeGroupToFactoryMap(factoryLink),
                exampleStatesMap,
                this.exampleStateConvergenceChecker,
                exampleStatesMap.size(),
                0, this.nodeCount);

        // Verify that state was synced with restarted node.
        Operation op = Operation.createGet(owner, state.documentSelfLink);
        ExampleServiceState newState = sender.sendAndWait(op, ExampleServiceState.class);

        assertNotNull(newState);
        return newState;
    }

    @Test
    public void  synchAfterClusterRestart() throws Throwable {
        setUpMultiNode();
        String factoryLink = ExampleService.FACTORY_LINK;
        this.host.setNodeGroupQuorum(this.nodeCount - 1);
        this.host.waitForNodeGroupConvergence();

        List<ExampleServiceState> exampleStates = this.host.createExampleServices(
                this.host.getPeerHost(), this.serviceCount, null, factoryLink);

        Map<String, ExampleServiceState> exampleStatesMap =
                exampleStates.stream().collect(Collectors.toMap(s -> s.documentSelfLink, s -> s));

        this.host.waitForReplicatedFactoryChildServiceConvergence(
                this.host.getNodeGroupToFactoryMap(factoryLink),
                exampleStatesMap,
                this.exampleStateConvergenceChecker,
                exampleStatesMap.size(),
                0, this.nodeCount);

        List<VerificationHost> hosts = new ArrayList<>();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -387,6 +387,7 @@
     }
 
     @Test
+    @Ignore
     public void  synchAfterClusterRestart() throws Throwable {
         setUpMultiNode();
         String factoryLink = ExampleService.FACTORY_LINK;
```
