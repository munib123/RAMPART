# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 2153_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2153_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 1517-1560 of the vulnerable file.

                    }
                }
                consumerExchanges.put(id, result);
            }
        }
        return result;
    }

    private void removeConsumerBrokerExchange(ConsumerId id) {
        synchronized (consumerExchanges) {
            consumerExchanges.remove(id);
        }
    }

    public int getProtocolVersion() {
        return protocolVersion.get();
    }

    @Override
    public Response processControlCommand(ControlCommand command) throws Exception {
        String control = command.getCommand();
        if (control != null && control.equals("shutdown")) {
            System.exit(0);
        }
        return null;
    }

    @Override
    public Response processMessageDispatch(MessageDispatch dispatch) throws Exception {
        return null;
    }

    @Override
    public Response processConnectionControl(ConnectionControl control) throws Exception {
        if (control != null) {
            faultTolerantConnection = control.isFaultTolerant();
        }
        return null;
    }

    @Override
    public Response processConnectionError(ConnectionError error) throws Exception {
        return null;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1534,10 +1534,6 @@
 
     @Override
     public Response processControlCommand(ControlCommand command) throws Exception {
-        String control = command.getCommand();
-        if (control != null && control.equals("shutdown")) {
-            System.exit(0);
-        }
         return null;
     }
 
```
