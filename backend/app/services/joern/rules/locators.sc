// RAMPART - Joern/CPG locator queries for the SAST-blind logic bugs that pattern
// scanners (semgrep/bandit) cannot see: IDOR, mass assignment, unchecked quantity, TOCTOU.
//
// Design: these are INTRAPROCEDURAL heuristics. pysrc2cpg's interprocedural edges are
// unreliable (dynamic dispatch / unresolved receiver types become external stubs), so every
// query reasons within a single method. Joern LOCATES candidates structurally; it does not
// prove them. The LLM verification step downstream confirms or rejects each one.
//
// __INPUT_DIR__, __OUT_FILE__, __DIAG_FILE__ and __PROJECT__ are substituted by scan.py
// (forward-slash paths). Output is TSV: cwe \t severity \t file \t line \t method \t rule \t message \t evidence
//
// TWO EXECUTION MODES, ONE FILE. Script mode (`joern --script`) runs this whole file. Server
// mode (P3) splits it on the `// @@ <section>` markers below and submits each section as its
// own /query-sync request against a long-lived REPL, so a compile error in one rule costs that
// rule and nothing else, and the JVM start is paid once per backend process. The REPL keeps
// vals across requests, which is what lets the sections share state. Keep every section
// self-contained in the sense that it only depends on sections ABOVE it.

// @@ prelude
import scala.collection.mutable.ListBuffer
import scala.util.control.NonFatal

val inputDir = "__INPUT_DIR__"
val outFile  = "__OUT_FILE__"
val diagFile = "__DIAG_FILE__"
val projName = "__PROJECT__"

val findings = ListBuffer[String]()
def san(s: String): String = s.replace("\t", " ").replace("\r", " ").replace("\n", " ").trim
def add(cwe: String, sev: String, file: String, line: Int, meth: String, rule: String, msg: String, ev: String): Unit =
  findings += List(cwe, sev, file, line.toString, meth, rule, san(msg), san(ev)).mkString("\t")

// Fix 1: a rule that THROWS must never look like a rule that found nothing. Every rule body is
// wrapped; a throw is recorded per rule and the run continues. scan.py reads diag.json after
// the run, so "ok" and "threw" are distinguishable. Before this, one throw anywhere skipped
// the os.write at the end and the whole target reported UNSCANNED.
val RULES = List("joern-idor-missing-ownership", "joern-mass-assignment",
                 "joern-unchecked-quantity", "joern-toctou-check-then-write")
val ruleErrors = scala.collection.mutable.Map[String, Int]().withDefaultValue(0)
val ruleFirst  = scala.collection.mutable.Map[String, String]()
val ruleRan    = scala.collection.mutable.Set[String]()
var methodsSeen  = 0
var methodsThrew = 0
def guarded(rule: String)(body: => Unit): Unit =
  try body catch { case NonFatal(e) =>
    ruleErrors(rule) += 1
    if (!ruleFirst.contains(rule))
      ruleFirst(rule) = san(s"${e.getClass.getSimpleName}: ${Option(e.getMessage).getOrElse("")}").take(200)
  }
def jstr(s: String): String = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

// Tokens whose PRESENCE in a method suppresses a candidate (a guard is there).
//
// Fix 2: authentication is not authorization. IDOR is BY DEFINITION a bug in code that a
// logged-in user reaches, so a token that only proves "the caller is logged in" must never
// suppress the IDOR rule - with login_required in the suppressor list, the rule went silent on
// every decorated view, which is every view in a real Flask-Login or Django app. Shopfast could
// not show this because it has no decorators at all.
//   AUTHZ      proves the caller may touch THIS record -> suppresses
//   AUTHN_ONLY proves the caller is logged in           -> never suppresses; becomes evidence
//              the LLM sees ("AUTHENTICATED_NOT_AUTHORIZED"), which is strictly better input
//              than silence.
// Fix 5: abort(401) / abort(403) are authorization outcomes; abort(404) is not-found and
// abort(400) is validation. The bare "abort(" token made a not-found guard read as authz.
val AUTHZ = List("is_owner", "owner_id", "check_owner", "has_permission", "authorize",
  "access_denied", "unauthorized", "forbidden", "abort(401", "abort(403",
  "permissiondenied", "permission_denied", "httpforbidden", "raise_403", "http_403")
val AUTHN_ONLY = List("current_user", "login_required", "requires_auth", "requires_login",
  "authenticated", "g.user", "current_identity", "session[", "session.get(")
val LOCK = List("lock", "acquire", "atomic", "select_for_update", "with_for_update", "for update",
  "begin(", "savepoint", "transaction", "serializable", "mutex", "semaphore")
// Fix 6: ' in [' / ' in (' / ' in {' matched ANY Python membership test anywhere in the method
// (an unrelated `if section in ["profile", "prefs"]`), silently suppressing CWE-915. An
// allow-list is named for what it is; the tokens below are names, not syntax.
val ALLOWLIST = List("allow", "whitelist", "permitted", "allowed_fields", "safe_fields",
  "editable_fields", "writable_fields", "fields = (", "fields = [", "only(")
val QTY = List("qty", "quantity", "amount", "count", "total", "price", "subtotal", "balance", "stock")

// @@ import
importCode.python(inputDir, projName)

// @@ context
// Fix 7 (part 1): the module-scope call table is computed ONCE. The July code ran
// cpg.method.name("<module>").filter(...).call.code.l inside the per-method loop - a full
// graph traversal plus materialisation per method, quadratic, and the first thing that dies
// on a 50k-LOC repo. Keyed by filename; values lowercased once.
val moduleCallsByFile: Map[String, List[String]] =
  cpg.method.nameExact("<module>").l
    .map(mm => mm.filename -> mm.call.code.l.map(_.toLowerCase))
    .groupBy(_._1).map { case (f, xs) => f -> xs.flatMap(_._2) }

// Everything a rule needs about one method, computed in ONE traversal. Rules iterate `ctxs`,
// so in server mode a rule that fails to compile leaves the contexts intact for the others.
case class Ctx(name: String, file: String, line: Int, params: List[String],
               signalText: String, guardText: String, execCode: List[String],
               hasAuthz: Boolean, authnNote: String,
               readCalls: List[String], setattrCalls: List[String],
               iterCalls: Int, multCode: List[String], cmpCode: List[String], commitCalls: Int) {
  def blobHas(toks: List[String])  = toks.exists(signalText.contains)
  def guardHas(toks: List[String]) = toks.exists(guardText.contains)
  def execHas(kw: String) = execCode.exists(_.toUpperCase.contains(kw))
}

// Fix 8: every .name(s) / .code(s) / .filename(s) accessor treats s as a REGEX. The July
// prototype lost an entire run to a Windows path in .filename() and then routed around it
// with .filter(_.filename == f). The hazard is deletable: nameExact / filenameExact /
// codeExact exist. Every literal match below uses nameExact; the one deliberate regex is the
// nameNot() that excludes synthetic scopes.
// Fix 4: name matchers are full-match regexes. pysrc2cpg names synthetic scopes "<lambda>0",
// "<comprehension>1", "<module>" - the trailing index digit meant "<.*>" did NOT match
// "<lambda>0", so lambdas were scanned as user methods and could fire a rule on their own.
def ctx(m: io.shiftleft.codepropertygraph.generated.nodes.Method): Ctx = {
  val name = m.name
  val file = m.filename
  // Fix 3: two channels, and the split is load-bearing.
  //   signalText  calls + literals + identifiers - what the method DOES and mentions
  //   guardText   calls + identifiers only       - what the method does; NO literals
  // Guards are tested against guardText, so a docstring or a string constant can never satisfy
  // one. Shopfast plants business-justification docstrings on purpose ("runs inside a
  // transaction with a row lock"); before this, "lock" in a docstring suppressed the TOCTOU
  // rule, and a docstring saying "not authorized" suppressed IDOR via the substring "authorize".
  // Nodes are joined with a 3-space separator so a token cannot match ACROSS two adjacent nodes.
  val SEP = "   "
  val calls  = m.ast.isCall.code.l
  val idents = m.ast.isIdentifier.name.l
  val signalText = (calls ++ m.ast.isLiteral.code.l ++ idents).mkString(SEP).toLowerCase
  val guardText  = (calls ++ idents).mkString(SEP).toLowerCase
  // Fix 7 (part 2): match the decorator lowering EXACTLY as "(def <name>(", not contains(name).
  // pysrc2cpg lowers @deco def view(...) to `view = deco(def view(...))` at module scope. With
  // contains(), `get_note_extra = check_owner(def get_note_extra(...))` credited the shorter,
  // undecorated sibling get_note with a guard it does not have.
  val decoAnchor  = "(def " + name.toLowerCase + "("
  val moduleCalls = moduleCallsByFile.getOrElse(file, Nil).filter(_.contains(decoAnchor))
  val hasAuthz = AUTHZ.exists(guardText.contains) || moduleCalls.exists(c => AUTHZ.exists(c.contains))
  val authnTok = (AUTHN_ONLY.filter(guardText.contains) ++
                  AUTHN_ONLY.filter(a => moduleCalls.exists(_.contains(a)))).distinct
  val authnNote = if (authnTok.nonEmpty && !hasAuthz) s" AUTHENTICATED_NOT_AUTHORIZED(${authnTok.mkString(",")})" else ""
  Ctx(
    name = name, file = file, line = m.lineNumber.getOrElse(-1),
    params = m.parameter.name.l.map(_.toLowerCase),
    signalText = signalText, guardText = guardText,
    execCode = m.call.nameExact("execute").code.l,
    hasAuthz = hasAuthz, authnNote = authnNote,
    readCalls = m.call.nameExact("fetchone", "first", "one", "scalar").code.l,
    setattrCalls = m.call.nameExact("setattr").code.l,
    iterCalls = m.call.nameExact("items", "to_dict", "keys", "values").size,
    multCode = m.call.nameExact("<operator>.multiplication").code.l,
    cmpCode = m.call.nameExact("<operator>.greaterThan", "<operator>.greaterEqualsThan",
                               "<operator>.lessThan", "<operator>.lessEqualsThan").code.l,
    commitCalls = m.call.nameExact("commit").size,
  )
}

val ctxs: List[Ctx] = cpg.method.isExternal(false).nameNot("<.*>\\d*", "__.*__").l.flatMap { m =>
  methodsSeen += 1
  try Some(ctx(m)) catch { case NonFatal(e) => methodsThrew += 1; None }
}

// @@ rule joern-idor-missing-ownership
ruleRan += "joern-idor-missing-ownership"
ctxs.foreach { c => guarded("joern-idor-missing-ownership") {
  val singleRead = c.readCalls.nonEmpty || c.execHas("SELECT")
  val idParam = c.params.exists(p => p == "id" || p.endsWith("_id"))
  if (singleRead && idParam && !c.hasAuthz) {
    val idName = c.params.find(p => p == "id" || p.endsWith("_id")).getOrElse("id")
    val ev = (c.readCalls ++ c.execCode).headOption.getOrElse("")
    add("CWE-639", "high", c.file, c.line, c.name, "joern-idor-missing-ownership",
      s"Reads a record by the caller-supplied id '${idName}' with no ownership or authorization check in the method. If this record is user-owned, any authenticated user can read another user's data (IDOR).${c.authnNote}", ev)
  }
}}

// @@ rule joern-mass-assignment
ruleRan += "joern-mass-assignment"
ctxs.foreach { c => guarded("joern-mass-assignment") {
  val iteratesData = c.iterCalls > 0 ||
    c.blobHas(List("request.form", "request.json", "**data", "**request", "**kwargs"))
  val updateWrite = c.execHas("UPDATE") || c.execHas("INSERT") || c.setattrCalls.nonEmpty
  if (iteratesData && updateWrite && !c.guardHas(ALLOWLIST)) {
    val ev = (c.execCode ++ c.setattrCalls).headOption.getOrElse("")
    add("CWE-915", "high", c.file, c.line, c.name, "joern-mass-assignment",
      "Writes every field of a caller-supplied data mapping into a record with no allow-list, so a client can set fields that were never meant to be user-writable (e.g. is_admin, role, balance).", ev)
  }
}}

// @@ rule joern-unchecked-quantity
ruleRan += "joern-unchecked-quantity"
ctxs.foreach { c => guarded("joern-unchecked-quantity") {
  val qtyMult = c.multCode.exists(x => QTY.exists(x.toLowerCase.contains))
  val posGuard = c.cmpCode.exists(x => QTY.exists(x.toLowerCase.contains)) ||
    c.guardHas(List("max(0", "abs(", "> 0", ">= 0", "> 1"))
  if (qtyMult && !posGuard) {
    val ev = c.multCode.headOption.getOrElse("")
    add("CWE-840", "medium", c.file, c.line, c.name, "joern-unchecked-quantity",
      "Computes a monetary amount from a caller-supplied quantity/price with no lower-bound (>0) guard. A negative or zero quantity can yield a negative total (store credit / free goods).", ev)
  }
}}

// @@ rule joern-toctou-check-then-write
ruleRan += "joern-toctou-check-then-write"
ctxs.foreach { c => guarded("joern-toctou-check-then-write") {
  val hasCheck = c.cmpCode.nonEmpty
  val hasWrite = c.execHas("UPDATE") || c.execHas("INSERT") || c.execHas("DELETE") || c.commitCalls > 0
  val checkOnResource = c.cmpCode.exists(x => QTY.exists(x.toLowerCase.contains))
  if (hasCheck && hasWrite && checkOnResource && !c.guardHas(LOCK)) {
    val ev = c.execCode.headOption.getOrElse("")
    add("CWE-362", "high", c.file, c.line, c.name, "joern-toctou-check-then-write",
      "Checks a resource value (e.g. stock/balance) and then mutates it in the same method with no lock or atomic transaction. Concurrent requests can both pass the check before either writes (TOCTOU race), oversubscribing the resource.", ev)
  }
}}

// @@ finish
// The always-write contract: findings.tsv exists even when clean, so scan.py can tell "clean"
// from "the locators never ran". diag.json says which rules ran and which threw; in server
// mode a rule whose section failed to COMPILE never adds itself to ruleRan, so it reports
// "not_run" here and scan.py upgrades that to "compile_error" from the /query-sync flag.
os.write.over(os.Path(outFile), findings.mkString("\n"))
val ruleState = RULES.map { r =>
  val st = if (!ruleRan.contains(r)) "not_run" else if (ruleErrors(r) == 0) "ok" else "threw"
  s"${jstr(r)}: {\"state\": ${jstr(st)}, \"errors\": ${ruleErrors(r)}, \"first_error\": ${jstr(ruleFirst.getOrElse(r, ""))}}"
}.mkString(", ")
os.write.over(os.Path(diagFile),
  s"""{"methods_seen": $methodsSeen, "methods_threw": $methodsThrew, "findings": ${findings.size}, "rule_state": {$ruleState}}""")
println(s"JOERN_FINDINGS=${findings.size}")
