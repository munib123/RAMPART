// @@ vocab
// The pack is read as DATA. scan.py has already validated it against vocab/schema.json and
// written the composed, canonical form; if this read still fails (truncated write, disk), the
// shipped _base pack is tried, and if THAT fails the section throws - in server mode scan.py
// treats a failing non-rule section as "phase did not run", which is the honest outcome: the
// rules must never run with empty guard lists (that is T-10: every method becomes a candidate).
def readPack(p: String): ujson.Value = ujson.read(os.read(os.Path(p)))
val (pack, packSource) =
  try (readPack(packFile), "pack")
  catch { case NonFatal(e) => (readPack(basePackFile), "base_fallback:" + e.getClass.getSimpleName) }
val packId = pack("pack_id").str
// Representation fix (P6, found on the DEV split): pysrc2cpg renders keyword arguments and
// assignments with spaces around the equals sign - `get_object_or_404(Order, pk = order_id,
// user = request.user)` - while every pack author writes tokens the way source and docs spell
// them: `user=request.user`, `min_value=1`, `fields=[`. Both the method text and every pack
// value are normalised to the compact form, so the two spellings are one token. `==`, `!=`,
// `>=`, `<=` contain no " = " and are untouched.
def norm(s: String): String = s.replace(" = ", "=")
def slot(name: String): List[String] = pack("slots")(name)("values").arr.map(v => norm(v.str)).toList.distinct

// ---- guards: tokens whose PRESENCE suppresses a candidate ----------------------------------
// Fix 2: authentication is not authorization. IDOR is BY DEFINITION a bug in code that a
// logged-in user reaches, so a token that only proves "the caller is logged in" must never
// suppress the IDOR rule.
//   AUTHZ      proves the caller may touch THIS record -> suppresses
//   AUTHN_ONLY proves the caller is logged in           -> never suppresses; becomes evidence
//              the LLM sees ("AUTHENTICATED_NOT_AUTHORIZED")
// Fix 5: abort(401) / abort(403) are authorization outcomes; abort(404) is not-found.
// Fix 6: an allow-list is named for what it is; the tokens are names, not syntax (' in [').
val AUTHZ       = slot("authz_guard")
val AUTHN_ONLY  = slot("authn_only")
val LOCK        = slot("lock_guard")
val ALLOWLIST   = slot("allowlist_guard")
val POS_GUARD   = slot("positive_guard")
val URL_GUARD   = slot("url_guard")              // a host / scheme allow-list on an outbound URL
val PATH_GUARD  = slot("path_guard")             // a sanitiser or containment check on a file path

// ---- signals and operand terms -------------------------------------------------------------
val MASS_SIGNAL = slot("mass_assign_signal")
val QTY_TERMS   = slot("qty_terms")
val PRICE_TERMS = slot("price_terms")
val QTY         = (QTY_TERMS ++ PRICE_TERMS).distinct   // the pre-P5 list was the union
val REQUEST_SRC = slot("request_sources")        // matched against a value's origin text
val CRED_TERMS  = slot("credential_terms")       // an operand that holds a credential
val AUTH_TERMS  = slot("auth_check_terms")       // a project function that checks credentials

// ---- sinks: call names (exact) and qualified call paths (prefix of the call code) ----------
val READ_CALLS  = slot("orm_read_calls")
val DYN_WRITE   = slot("dyn_write_calls")
val ITER_CALLS  = slot("mapping_iter_calls")
val COMMIT_CALLS = slot("commit_calls")
val EXEC_CALLS  = slot("exec_calls")
val SQL_READ    = slot("sql_read_kw")
val SQL_WRITE   = slot("sql_write_kw")
val SQL_DELETE  = slot("sql_delete_kw")
val ID_EXACT    = slot("id_param_exact")
val ID_SUFFIX   = slot("id_param_suffix")
val AUTH_CALLS  = slot("auth_check_calls")       // library credential checks whose result matters
val HTTP_CALLS  = slot("http_client_calls")      // outbound HTTP: requests.get, urlopen, ...
val FILE_CALLS  = slot("file_sink_calls")        // open, send_file, os.remove, ...
// P7 slots: class scope and routes. Empty in _base; framework packs fill them.
val SCOPED_READ = slot("scoped_read_calls")      // reads that go through the class queryset hook
val QS_HOOKS    = slot("queryset_hooks")         // class methods whose body scopes those reads
val OBJPERM_HOOKS = slot("object_permission_hooks") // a class defining one is object-level auth
val ROUTE_MARKERS = slot("route_markers")        // module-level calls that register a route
// keyword flows: "call:keyword=value", compared with == after constant resolution
val XXE_KWARGS   = slot("xxe_kwargs").toSet
val DEBUG_KWARGS = slot("debug_kwargs").toSet

// Sets for the per-method name filters: one pass over a method's calls instead of one graph
// traversal per slot. nameExact(xs: _*) and Set.contains are the same exact-equality test.
val READ_SET    = (READ_CALLS ++ SCOPED_READ).toSet
val SCOPED_SET  = SCOPED_READ.toSet
val DYN_SET     = DYN_WRITE.toSet
val ITER_SET    = ITER_CALLS.toSet
val COMMIT_SET  = COMMIT_CALLS.toSet
val EXEC_SET    = EXEC_CALLS.toSet
val AUTH_CALL_SET = AUTH_CALLS.toSet
