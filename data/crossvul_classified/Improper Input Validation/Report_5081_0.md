# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 5081_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5081_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 2614-2654 of the vulnerable file.

  }

  string prefix;
  vector<string> fullcmd;
  map<string, cmd_vartype> cmdmap;
  stringstream ss, ds;
  bufferlist rdata;
  string rs;
  int r = -EINVAL;
  rs = "unrecognized command";

  if (!cmdmap_from_json(m->cmd, &cmdmap, ss)) {
    // ss has reason for failure
    r = -EINVAL;
    rs = ss.str();
    if (!m->get_source().is_mon())  // don't reply to mon->mon commands
      reply_command(op, r, rs, 0);
    return;
  }

  cmd_getval(g_ceph_context, cmdmap, "prefix", prefix);
  if (prefix == "get_command_descriptions") {
    bufferlist rdata;
    Formatter *f = Formatter::create("json");
    format_command_descriptions(leader_supported_mon_commands,
				leader_supported_mon_commands_size, f, &rdata);
    delete f;
    reply_command(op, 0, "", rdata, 0);
    return;
  }

  string module;
  string err;

  dout(0) << "handle_command " << *m << dendl;

  string format;
  cmd_getval(g_ceph_context, cmdmap, "format", format, string("plain"));
  boost::scoped_ptr<Formatter> f(Formatter::create(format));

  get_str_vec(prefix, fullcmd);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2631,7 +2631,19 @@
     return;
   }
 
-  cmd_getval(g_ceph_context, cmdmap, "prefix", prefix);
+  // check return value. If no prefix parameter provided,
+  // return value will be false, then return error info.
+  if(!cmd_getval(g_ceph_context, cmdmap, "prefix", prefix)) {
+    reply_command(op, -EINVAL, "command prefix not found", 0);
+    return;
+  }
+
+  // check prefix is empty
+  if (prefix.empty()) {
+    reply_command(op, -EINVAL, "command prefix must not be empty", 0);
+    return;
+  }
+
   if (prefix == "get_command_descriptions") {
     bufferlist rdata;
     Formatter *f = Formatter::create("json");
@@ -2652,6 +2664,15 @@
   boost::scoped_ptr<Formatter> f(Formatter::create(format));
 
   get_str_vec(prefix, fullcmd);
+
+  // make sure fullcmd is not empty.
+  // invalid prefix will cause empty vector fullcmd.
+  // such as, prefix=";,,;"
+  if (fullcmd.empty()) {
+    reply_command(op, -EINVAL, "command requires a prefix to be valid", 0);
+    return;
+  }
+
   module = fullcmd[0];
 
   // validate command is in leader map
```
