# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in xml
**Pair ID:** 3878_4
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3878_4`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```xml
Lines 19-57 of the vulnerable file.

<!--  See src/resources/configuration/ReadMe.txt for how the configuration assembly works -->
<config>
    <extension-module>org.jboss.as.connector</extension-module>
    <subsystem xmlns="urn:jboss:domain:datasources:5.0">
        <datasources>
            <datasource jndi-name="java:jboss/datasources/ExampleDS" pool-name="ExampleDS" enabled="true" use-java-context="true" statistics-enabled="${wildfly.datasources.statistics-enabled:${wildfly.statistics-enabled:false}}">
                <connection-url>jdbc:h2:mem:test;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE</connection-url>
                <driver>h2</driver>
                <security>
                    <user-name>sa</user-name>
                    <password>sa</password>
                </security>
            </datasource>
            <datasource jndi-name="java:jboss/datasources/KeycloakDS" pool-name="KeycloakDS" enabled="true" use-java-context="true" statistics-enabled="${wildfly.datasources.statistics-enabled:${wildfly.statistics-enabled:false}}">
                <connection-url><?KEYCLOAK_DS_CONNECTION_URL?></connection-url>
                <driver>h2</driver>
                <security>
                    <user-name>sa</user-name>
                    <password>sa</password>
                </security>
            </datasource>
            <drivers>
                <driver name="h2" module="com.h2database.h2">
                    <xa-datasource-class>org.h2.jdbcx.JdbcDataSource</xa-datasource-class>
                </driver>
            </drivers>
        </datasources>
    </subsystem>
    <supplement name="default">
        <replacement placeholder="KEYCLOAK_DS_CONNECTION_URL">
            jdbc:h2:${jboss.server.data.dir}/keycloak;AUTO_SERVER=TRUE
        </replacement>
    </supplement>
    <supplement name="domain">
        <replacement placeholder="KEYCLOAK_DS_CONNECTION_URL">
            jdbc:h2:${jboss.server.data.dir}/../../shared-database/keycloak;AUTO_SERVER=TRUE
        </replacement>
    </supplement>
</config>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,9 @@
                     <user-name>sa</user-name>
                     <password>sa</password>
                 </security>
+                <pool>
+                    <max-pool-size>100</max-pool-size>
+                </pool>
             </datasource>
             <drivers>
                 <driver name="h2" module="com.h2database.h2">
```
