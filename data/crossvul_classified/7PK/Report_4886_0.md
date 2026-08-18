# CrossVul Fix Pair: 7PK in c
**Pair ID:** 4886_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4886_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```c
Lines 10917-10957 of the vulnerable file.

 * @seconds and @nseconds. The @seconds represents the number of
 * seconds since the UNIX Epoch of 1970-01-01 00:00:00 in UTC.
 *
 * Please note that some hypervisors may require guest agent to
 * be configured and running in order to run this API.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virDomainGetTime(virDomainPtr dom,
                 long long *seconds,
                 unsigned int *nseconds,
                 unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "seconds=%p, nseconds=%p, flags=%x",
                     seconds, nseconds, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);

    if (dom->conn->driver->domainGetTime) {
        int ret = dom->conn->driver->domainGetTime(dom, seconds,
                                                   nseconds, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainSetTime:
 * @dom: a domain object
 * @seconds: time to set
 * @nseconds: the nanosecond part of @seconds
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10934,6 +10934,7 @@
     virResetLastError();
 
     virCheckDomainReturn(dom, -1);
+    virCheckReadOnlyGoto(dom->conn->flags, error);
 
     if (dom->conn->driver->domainGetTime) {
         int ret = dom->conn->driver->domainGetTime(dom, seconds,
```
