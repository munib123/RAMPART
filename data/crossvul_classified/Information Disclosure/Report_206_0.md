# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 206_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `206_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 46-86 of the vulnerable file.

    PS_VLOG(1) << my_node_.ShortDebugString() << " is stopping";
    Van::Stop();
    // close sockets
    int linger = 0;
    int rc = zmq_setsockopt(receiver_, ZMQ_LINGER, &linger, sizeof(linger));
    CHECK(rc == 0 || errno == ETERM);
    CHECK_EQ(zmq_close(receiver_), 0);
    for (auto& it : senders_) {
      int rc = zmq_setsockopt(it.second, ZMQ_LINGER, &linger, sizeof(linger));
      CHECK(rc == 0 || errno == ETERM);
      CHECK_EQ(zmq_close(it.second), 0);
    }
    zmq_ctx_destroy(context_);
  }

  int Bind(const Node& node, int max_retry) override {
    receiver_ = zmq_socket(context_, ZMQ_ROUTER);
    CHECK(receiver_ != NULL)
        << "create receiver socket failed: " << zmq_strerror(errno);
    int local = GetEnv("DMLC_LOCAL", 0);
    std::string addr = local ? "ipc:///tmp/" : "tcp://*:";
    int port = node.port;
    unsigned seed = static_cast<unsigned>(time(NULL)+port);
    for (int i = 0; i < max_retry+1; ++i) {
      auto address = addr + std::to_string(port);
      if (zmq_bind(receiver_, address.c_str()) == 0) break;
      if (i == max_retry) {
        port = -1;
      } else {
        port = 10000 + rand_r(&seed) % 40000;
      }
    }
    return port;
  }

  void Connect(const Node& node) override {
    CHECK_NE(node.id, node.kEmpty);
    CHECK_NE(node.port, node.kEmpty);
    CHECK(node.hostname.size());
    int id = node.id;
    auto it = senders_.find(id);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,7 +63,8 @@
     CHECK(receiver_ != NULL)
         << "create receiver socket failed: " << zmq_strerror(errno);
     int local = GetEnv("DMLC_LOCAL", 0);
-    std::string addr = local ? "ipc:///tmp/" : "tcp://*:";
+    std::string hostname = node.hostname.empty() ? "*" : node.hostname;
+    std::string addr = local ? "ipc:///tmp/" : "tcp://" + hostname + ":";
     int port = node.port;
     unsigned seed = static_cast<unsigned>(time(NULL)+port);
     for (int i = 0; i < max_retry+1; ++i) {
```
