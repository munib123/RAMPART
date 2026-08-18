# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 134_16
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_16`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 106-148 of the vulnerable file.

  int init(uint64_t gid, entity_addr_t client_addr);
  void shutdown();

  entity_addr_t get_myaddr() const;

  DaemonServer(MonClient *monc_,
               Finisher &finisher_,
	       DaemonStateIndex &daemon_state_,
	       ClusterState &cluster_state_,
	       PyModuleRegistry &py_modules_,
	       LogChannelRef cl,
	       LogChannelRef auditcl);
  ~DaemonServer() override;

  bool ms_dispatch(Message *m) override;
  bool ms_handle_reset(Connection *con) override;
  void ms_handle_remote_reset(Connection *con) override {}
  bool ms_handle_refused(Connection *con) override;
  bool ms_get_authorizer(int dest_type, AuthAuthorizer **authorizer,
                         bool force_new) override;
  bool ms_verify_authorizer(Connection *con,
      int peer_type,
      int protocol,
      ceph::bufferlist& authorizer,
      ceph::bufferlist& authorizer_reply,
      bool& isvalid,
      CryptoKey& session_key) override;

  bool handle_open(MMgrOpen *m);
  bool handle_report(MMgrReport *m);
  bool handle_command(MCommand *m);
  void send_report();
  void got_service_map();

  void _send_configure(ConnectionRef c);

  virtual const char** get_tracked_conf_keys() const override;
  virtual void handle_conf_change(const struct md_config_t *conf,
                          const std::set <std::string> &changed) override;
};

#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -123,13 +123,15 @@
   bool ms_handle_refused(Connection *con) override;
   bool ms_get_authorizer(int dest_type, AuthAuthorizer **authorizer,
                          bool force_new) override;
-  bool ms_verify_authorizer(Connection *con,
-      int peer_type,
-      int protocol,
-      ceph::bufferlist& authorizer,
-      ceph::bufferlist& authorizer_reply,
-      bool& isvalid,
-      CryptoKey& session_key) override;
+  bool ms_verify_authorizer(
+    Connection *con,
+    int peer_type,
+    int protocol,
+    ceph::bufferlist& authorizer,
+    ceph::bufferlist& authorizer_reply,
+    bool& isvalid,
+    CryptoKey& session_key,
+    std::unique_ptr<AuthAuthorizerChallenge> *challenge) override;
 
   bool handle_open(MMgrOpen *m);
   bool handle_report(MMgrReport *m);
```
