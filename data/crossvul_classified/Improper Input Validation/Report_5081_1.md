# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 5081_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5081_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 28-68 of the vulnerable file.


  char *buf, *st;
  size_t buflen, stlen;
  char *cmd[2];

  cmd[1] = NULL;

  cmd[0] = (char *)"{\"prefix\":\"get_command_descriptions\"}";
  ASSERT_EQ(0, rados_mon_command(cluster, (const char **)cmd, 1, "", 0, &buf, &buflen, &st, &stlen));
  ASSERT_LT(0u, buflen);
  rados_buffer_free(buf);
  rados_buffer_free(st);

  cmd[0] = (char *)"get_command_descriptions";
  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "", 0, &buf, &buflen, &st, &stlen));
  rados_buffer_free(buf);
  rados_buffer_free(st);

  cmd[0] = (char *)"asdfqwer";
  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "{}", 2, &buf, &buflen, &st, &stlen));
  rados_buffer_free(buf);
  rados_buffer_free(st);

  cmd[0] = (char *)"{\"prefix\":\"mon_status\"}";
  ASSERT_EQ(0, rados_mon_command(cluster, (const char **)cmd, 1, "", 0, &buf, &buflen, &st, &stlen));
  ASSERT_LT(0u, buflen);
  //ASSERT_LT(0u, stlen);
  rados_buffer_free(buf);
  rados_buffer_free(st);
  rados_shutdown(cluster);
}

TEST(LibRadosCmd, MonDescribePP) {
  Rados cluster;
  ASSERT_EQ("", connect_cluster_pp(cluster));
  bufferlist inbl, outbl;
  string outs;
  ASSERT_EQ(0, cluster.mon_command("{\"prefix\": \"get_command_descriptions\"}",
				   inbl, &outbl, &outs));
  ASSERT_LT(0u, outbl.length());
  ASSERT_LE(0u, outs.length());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,6 +45,41 @@
 
   cmd[0] = (char *)"asdfqwer";
   ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "{}", 2, &buf, &buflen, &st, &stlen));
+  rados_buffer_free(buf);
+  rados_buffer_free(st);
+
+  cmd[0] = (char *)"";
+  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "{}", 2, &buf, &buflen, &st, &stlen));
+  rados_buffer_free(buf);
+  rados_buffer_free(st);
+
+  cmd[0] = (char *)"{}";
+  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "", 0, &buf, &buflen, &st, &stlen));
+  rados_buffer_free(buf);
+  rados_buffer_free(st);
+
+  cmd[0] = (char *)"{\"abc\":\"something\"}";
+  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "", 0, &buf, &buflen, &st, &stlen));
+  rados_buffer_free(buf);
+  rados_buffer_free(st);
+
+  cmd[0] = (char *)"{\"prefix\":\"\"}";
+  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "", 0, &buf, &buflen, &st, &stlen));
+  rados_buffer_free(buf);
+  rados_buffer_free(st);
+
+  cmd[0] = (char *)"{\"prefix\":\"    \"}";
+  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "", 0, &buf, &buflen, &st, &stlen));
+  rados_buffer_free(buf);
+  rados_buffer_free(st);
+
+  cmd[0] = (char *)"{\"prefix\":\";;;,,,;;,,\"}";
+  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "", 0, &buf, &buflen, &st, &stlen));
+  rados_buffer_free(buf);
+  rados_buffer_free(st);
+
+  cmd[0] = (char *)"{\"prefix\":\"extra command\"}";
+  ASSERT_EQ(-EINVAL, rados_mon_command(cluster, (const char **)cmd, 1, "", 0, &buf, &buflen, &st, &stlen));
   rados_buffer_free(buf);
   rados_buffer_free(st);
 
```
