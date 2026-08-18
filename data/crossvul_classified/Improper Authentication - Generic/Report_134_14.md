# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 134_14
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_14`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 91-131 of the vulnerable file.

   * such that deleting xlists doesn't assert.
   */
  bool is_clean_shutdown();

  // config observer bits
  const char** get_tracked_conf_keys() const override;
  void handle_conf_change(const struct md_config_t *conf,
				  const std::set <std::string> &changed) override;
 protected:
  // tick and other timer fun
  Context *tick_event = nullptr;
  void     reset_tick();

  void wait_for_omap_osds();

 private:
  bool ms_dispatch(Message *m) override;
  bool ms_get_authorizer(int dest_type, AuthAuthorizer **authorizer, bool force_new) override;
  bool ms_verify_authorizer(Connection *con, int peer_type,
			       int protocol, bufferlist& authorizer_data, bufferlist& authorizer_reply,
			       bool& isvalid, CryptoKey& session_key) override;
  void ms_handle_accept(Connection *con) override;
  void ms_handle_connect(Connection *con) override;
  bool ms_handle_reset(Connection *con) override;
  void ms_handle_remote_reset(Connection *con) override;
  bool ms_handle_refused(Connection *con) override;

 protected:
  // admin socket handling
  friend class MDSSocketHook;
  class MDSSocketHook *asok_hook;
  void set_up_admin_socket();
  void clean_up_admin_socket();
  void check_ops_in_flight(); // send off any slow ops to monitor
  bool asok_command(string command, cmdmap_t& cmdmap, string format,
		    ostream& ss);

  void dump_status(Formatter *f);

  /**
   * Terminate this daemon process.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -108,7 +108,8 @@
   bool ms_get_authorizer(int dest_type, AuthAuthorizer **authorizer, bool force_new) override;
   bool ms_verify_authorizer(Connection *con, int peer_type,
 			       int protocol, bufferlist& authorizer_data, bufferlist& authorizer_reply,
-			       bool& isvalid, CryptoKey& session_key) override;
+			    bool& isvalid, CryptoKey& session_key,
+			    std::unique_ptr<AuthAuthorizerChallenge> *challenge) override;
   void ms_handle_accept(Connection *con) override;
   void ms_handle_connect(Connection *con) override;
   bool ms_handle_reset(Connection *con) override;
```
