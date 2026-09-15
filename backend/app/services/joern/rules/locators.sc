// RAMPART - Joern/CPG locator queries for the SAST-blind logic bugs that pattern
// scanners (semgrep/bandit) cannot see: IDOR, mass assignment, unchecked quantity, TOCTOU.
//
// Design: these are INTRAPROCEDURAL heuristics. pysrc2cpg's interprocedural edges are
// unreliable (dynamic dispatch / unresolved receiver types become external stubs), so every
// query reasons within a single method. Joern LOCATES candidates structurally; it does not
// prove them. The LLM verification step downstream confirms or rejects each one.
//
// __INPUT_DIR__ and __OUT_FILE__ are substituted by joern_scan.py (forward-slash paths).
// Output is TSV: cwe \t severity \t file \t line \t method \t rule \t message \t evidence
import scala.collection.mutable.ListBuffer

val inputDir = "__INPUT_DIR__"
val outFile  = "__OUT_FILE__"
val projName = "__PROJECT__"

importCode.python(inputDir, projName)

val findings = ListBuffer[String]()
def san(s: String): String = s.replace("\t", " ").replace("\r", " ").replace("\n", " ").trim
def add(cwe: String, sev: String, file: String, line: Int, meth: String, rule: String, msg: String, ev: String): Unit =
  findings += List(cwe, sev, file, line.toString, meth, rule, san(msg), san(ev)).mkString("\t")

// Tokens whose PRESENCE in a method suppresses a candidate (a guard is there).
val AUTH = List("current_user", "login_required", "requires_auth", "requires_login", "authorize",
  "authenticated", "is_owner", "owner_id", "check_owner", "abort(", "g.user", "current_identity",
  "has_permission", "access_denied", "unauthorized", "forbidden")
val LOCK = List("lock", "acquire", "atomic", "select_for_update", "with_for_update", "for update",
  "begin(", "savepoint", "transaction", "serializable", "mutex", "semaphore")
val ALLOWLIST = List("allow", "whitelist", "permitted", "allowed_fields", " in [", " in (", " in {")
val QTY = List("qty", "quantity", "amount", "count", "total", "price", "subtotal", "balance", "stock")

cpg.method.isExternal(false).nameNot("<.*>", "__.*__").foreach { m =>
  val name = m.name
  val file = m.filename
  val line = m.lineNumber.getOrElse(-1)
  val params = m.parameter.name.l.map(_.toLowerCase)
  // token blob: every call code + literal + identifier name in the method body, lowercased
  val blob = (m.ast.isCall.code.l ++ m.ast.isLiteral.code.l ++ m.ast.isIdentifier.name.l)
    .mkString(" ").toLowerCase
  def blobHas(toks: List[String]) = toks.exists(blob.contains)

  val execCode = m.call.name("execute").code.l
  def execHas(kw: String) = execCode.exists(_.toUpperCase.contains(kw))
  val hasAuth = blobHas(AUTH)
  // decorator-based auth: pysrc2cpg lowers @login_required(view) to a module-scope wrapping
  // call, invisible to an in-method scan, so check the module for a decorator wrapping this method.
  // NB: .filename(s) matches s as a REGEX, and m.filename is an import-root-relative path that
  // uses the platform separator ("split\jobs.py" on Windows). Feeding that to a regex either
  // throws (\j = illegal escape) or silently matches nothing (\d = digit class), so compare the
  // filename as a plain string instead. See the equality filter below - do not reintroduce regex.
  val decoAuth = cpg.method.name("<module>").filter(_.filename == file).call.code.l
    .exists(c => c.contains(name) && AUTH.exists(a => c.toLowerCase.contains(a)))
  val protectedM = hasAuth || decoAuth

  // ---- IDOR / missing authorization (CWE-639) ----
  val singleRead = m.call.name("fetchone", "first", "one", "scalar").nonEmpty || execHas("SELECT")
  val idParam = params.exists(p => p == "id" || p.endsWith("_id"))
  if (singleRead && idParam && !protectedM) {
    val idName = params.find(p => p == "id" || p.endsWith("_id")).getOrElse("id")
    val ev = (m.call.name("fetchone").code.l ++ m.call.name("execute").code.l).headOption.getOrElse("")
    add("CWE-639", "high", file, line, name, "joern-idor-missing-ownership",
      s"Reads a record by the caller-supplied id '${idName}' with no ownership or authorization check in the method. If this record is user-owned, any authenticated user can read another user's data (IDOR).", ev)
  }

  // ---- Mass assignment (CWE-915) ----
  val iteratesData = m.call.name("items", "to_dict", "keys", "values").nonEmpty ||
    blobHas(List("request.form", "request.json", "**data", "**request", "**kwargs"))
  val updateWrite = execHas("UPDATE") || execHas("INSERT") || m.call.name("setattr").nonEmpty
  if (iteratesData && updateWrite && !blobHas(ALLOWLIST)) {
    val ev = (m.call.name("execute").code.l ++ m.call.name("setattr").code.l).headOption.getOrElse("")
    add("CWE-915", "high", file, line, name, "joern-mass-assignment",
      "Writes every field of a caller-supplied data mapping into a record with no allow-list, so a client can set fields that were never meant to be user-writable (e.g. is_admin, role, balance).", ev)
  }

  // ---- Unchecked quantity / business logic (CWE-840) ----
  val qtyMult = m.call.name("<operator>.multiplication").code.exists(c => QTY.exists(c.toLowerCase.contains))
  val posGuard = m.call.name("<operator>.greaterThan", "<operator>.greaterEqualsThan",
    "<operator>.lessThan", "<operator>.lessEqualsThan").code.exists(c => QTY.exists(c.toLowerCase.contains)) ||
    blobHas(List("max(0", "abs(", "> 0", ">= 0", "> 1"))
  if (qtyMult && !posGuard) {
    val ev = m.call.name("<operator>.multiplication").code.l.headOption.getOrElse("")
    add("CWE-840", "medium", file, line, name, "joern-unchecked-quantity",
      "Computes a monetary amount from a caller-supplied quantity/price with no lower-bound (>0) guard. A negative or zero quantity can yield a negative total (store credit / free goods).", ev)
  }

  // ---- Race condition / TOCTOU (CWE-362) ----
  val cmpCalls = m.call.name("<operator>.greaterThan", "<operator>.greaterEqualsThan",
    "<operator>.lessThan", "<operator>.lessEqualsThan")
  val hasCheck = cmpCalls.nonEmpty
  val hasWrite = execHas("UPDATE") || execHas("INSERT") || execHas("DELETE") || m.call.name("commit").nonEmpty
  val checkOnResource = cmpCalls.code.exists(c => QTY.exists(c.toLowerCase.contains))
  if (hasCheck && hasWrite && checkOnResource && !blobHas(LOCK)) {
    val ev = m.call.name("execute").code.l.headOption.getOrElse("")
    add("CWE-362", "high", file, line, name, "joern-toctou-check-then-write",
      "Checks a resource value (e.g. stock/balance) and then mutates it in the same method with no lock or atomic transaction. Concurrent requests can both pass the check before either writes (TOCTOU race), oversubscribing the resource.", ev)
  }
}

os.write.over(os.Path(outFile), findings.mkString("\n"))
println(s"JOERN_FINDINGS=${findings.size}")
