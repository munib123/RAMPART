// RAMPART - Joern/CPG locator queries for the SAST-blind logic bugs that pattern
// scanners (semgrep/bandit) cannot see: IDOR, mass assignment, unchecked quantity, TOCTOU.
//
// Design: these are INTRAPROCEDURAL heuristics. pysrc2cpg's interprocedural edges are
// unreliable (dynamic dispatch / unresolved receiver types become external stubs), so every
// query reasons within a single method. Joern LOCATES candidates structurally; it does not
// prove them. The LLM verification step downstream confirms or rejects each one.
//
// __INPUT_DIR__, __OUT_FILE__, __DIAG_FILE__, __PROJECT__, __PACK_FILE__, __BASE_PACK_FILE__
// and __PACK_TAG__ are substituted by scan.py (forward-slash paths). Output is TSV:
//   cwe \t severity \t file \t line \t method \t rule \t message \t evidence \t pack_tag \t slot_trace
// Columns 9-10 are provenance (P5): which pack, and which slot=value made the rule fire.
//
// VOCABULARY IS DATA (P5). This file holds the four rule SHAPES and nothing framework-specific.
// Every token list - what an ownership check, a lock, an allow-list or an object id LOOKS LIKE -
// comes from a JSON vocabulary pack (vocab/packs/*.json) that scan.py validates against
// vocab/schema.json and writes into the scratch dir. The `// @@ vocab` section reads it with
// ujson after importCode. A pack can only ever supply strings that reach String.contains,
// nameExact, == or endsWith; nothing from a pack is ever compiled, and no accessor that treats
// its argument as a regex ever sees a pack value. This Scala is frozen and hashed; the pack is
// what varies per target - so `--pack A` vs `--pack B` on one testbed is a clean ablation.
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

val inputDir     = "__INPUT_DIR__"
val outFile      = "__OUT_FILE__"
val diagFile     = "__DIAG_FILE__"
val projName     = "__PROJECT__"
val packFile     = "__PACK_FILE__"
val basePackFile = "__BASE_PACK_FILE__"
val packTag      = "__PACK_TAG__"        // "<pack_id>@<sha256[:12]>", column 9 of every finding

val findings = ListBuffer[String]()
def san(s: String): String = s.replace("\t", " ").replace("\r", " ").replace("\n", " ").trim
def add(cwe: String, sev: String, file: String, line: Int, meth: String, rule: String, msg: String, ev: String, trace: String): Unit =
  findings += List(cwe, sev, file, line.toString, meth, rule, san(msg), san(ev), packTag, san(trace)).mkString("\t")
// slot trace helpers: "slot=value" for the first value of `toks` found in `text` (contains),
// so the report can say WHICH vocabulary entry made the rule fire.
def hit(slot: String, toks: List[String], text: String): String =
  toks.find(text.contains).map(v => slot + "=" + v).getOrElse("")
def hitAny(slot: String, toks: List[String], texts: List[String]): String =
  toks.find(t => texts.exists(_.contains(t))).map(v => slot + "=" + v).getOrElse("")
def trace(parts: String*): String = parts.filter(_.nonEmpty).mkString(";")

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

// @@ import
importCode.python(inputDir, projName)

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
def slot(name: String): List[String] = pack("slots")(name)("values").arr.map(_.str).toList

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
// Fix 6: ' in [' / ' in (' / ' in {' matched ANY Python membership test anywhere in the method
// (an unrelated `if section in ["profile", "prefs"]`), silently suppressing CWE-915. An
// allow-list is named for what it is; the tokens are names, not syntax.
// (The values themselves live in vocab/packs/_base.json and the framework packs.)
val AUTHZ       = slot("authz_guard")
val AUTHN_ONLY  = slot("authn_only")
val LOCK        = slot("lock_guard")
val ALLOWLIST   = slot("allowlist_guard")
val POS_GUARD   = slot("positive_guard")
val MASS_SIGNAL = slot("mass_assign_signal")
val QTY_TERMS   = slot("qty_terms")
val PRICE_TERMS = slot("price_terms")
val QTY         = (QTY_TERMS ++ PRICE_TERMS).distinct   // the pre-P5 list was the union
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
  def execHas(kws: List[String]) = kws.exists(kw => execCode.exists(_.toUpperCase.contains(kw)))
  def execHit(slotName: String, kws: List[String]): String =
    kws.find(kw => execCode.exists(_.toUpperCase.contains(kw))).map(v => slotName + "=" + v).getOrElse("")
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
    // call_name slots reach nameExact ONLY - exact string equality, never a regex.
    execCode = m.call.nameExact(EXEC_CALLS: _*).code.l,
    hasAuthz = hasAuthz, authnNote = authnNote,
    readCalls = m.call.nameExact(READ_CALLS: _*).code.l,
    setattrCalls = m.call.nameExact(DYN_WRITE: _*).code.l,
    iterCalls = m.call.nameExact(ITER_CALLS: _*).size,
    // the operators are rule SHAPE, not vocabulary: they stay here
    multCode = m.call.nameExact("<operator>.multiplication").code.l,
    cmpCode = m.call.nameExact("<operator>.greaterThan", "<operator>.greaterEqualsThan",
                               "<operator>.lessThan", "<operator>.lessEqualsThan").code.l,
    commitCalls = m.call.nameExact(COMMIT_CALLS: _*).size,
  )
}

val ctxs: List[Ctx] = cpg.method.isExternal(false).nameNot("<.*>\\d*", "__.*__").l.flatMap { m =>
  methodsSeen += 1
  try Some(ctx(m)) catch { case NonFatal(e) => methodsThrew += 1; None }
}

// @@ rule joern-idor-missing-ownership
ruleRan += "joern-idor-missing-ownership"
ctxs.foreach { c => guarded("joern-idor-missing-ownership") {
  val singleRead = c.readCalls.nonEmpty || c.execHas(SQL_READ)
  def isId(p: String) = ID_EXACT.contains(p) || ID_SUFFIX.exists(p.endsWith)
  val idParam = c.params.exists(isId)
  if (singleRead && idParam && !c.hasAuthz) {
    val idName = c.params.find(isId).getOrElse("id")
    val ev = (c.readCalls ++ c.execCode).headOption.getOrElse("")
    val idTrace = if (ID_EXACT.contains(idName)) "id_param_exact=" + idName
                  else ID_SUFFIX.find(idName.endsWith).map("id_param_suffix=" + _).getOrElse("")
    val readTrace = READ_CALLS.find(r => c.readCalls.exists(_.contains(r + "("))).map("orm_read_calls=" + _)
                      .getOrElse(c.execHit("sql_read_kw", SQL_READ))
    add("CWE-639", "high", c.file, c.line, c.name, "joern-idor-missing-ownership",
      s"Reads a record by the caller-supplied id '${idName}' with no ownership or authorization check in the method. If this record is user-owned, any authenticated user can read another user's data (IDOR).${c.authnNote}", ev,
      trace(idTrace, readTrace))
  }
}}

// @@ rule joern-mass-assignment
ruleRan += "joern-mass-assignment"
ctxs.foreach { c => guarded("joern-mass-assignment") {
  val iteratesData = c.iterCalls > 0 || c.blobHas(MASS_SIGNAL)
  val updateWrite = c.execHas(SQL_WRITE) || c.setattrCalls.nonEmpty
  if (iteratesData && updateWrite && !c.guardHas(ALLOWLIST)) {
    val ev = (c.execCode ++ c.setattrCalls).headOption.getOrElse("")
    val sigTrace = if (c.iterCalls > 0) "mapping_iter_calls" else hit("mass_assign_signal", MASS_SIGNAL, c.signalText)
    val wrTrace = if (c.setattrCalls.nonEmpty)
                    DYN_WRITE.find(w => c.setattrCalls.exists(_.contains(w + "("))).map("dyn_write_calls=" + _).getOrElse("dyn_write_calls")
                  else c.execHit("sql_write_kw", SQL_WRITE)
    add("CWE-915", "high", c.file, c.line, c.name, "joern-mass-assignment",
      "Writes every field of a caller-supplied data mapping into a record with no allow-list, so a client can set fields that were never meant to be user-writable (e.g. is_admin, role, balance).", ev,
      trace(sigTrace, wrTrace))
  }
}}

// @@ rule joern-unchecked-quantity
ruleRan += "joern-unchecked-quantity"
ctxs.foreach { c => guarded("joern-unchecked-quantity") {
  val multLc = c.multCode.map(_.toLowerCase)
  val qtyMult = multLc.exists(x => QTY.exists(x.contains))
  val posGuard = c.cmpCode.exists(x => QTY.exists(x.toLowerCase.contains)) || c.guardHas(POS_GUARD)
  if (qtyMult && !posGuard) {
    val ev = c.multCode.headOption.getOrElse("")
    add("CWE-840", "medium", c.file, c.line, c.name, "joern-unchecked-quantity",
      "Computes a monetary amount from a caller-supplied quantity/price with no lower-bound (>0) guard. A negative or zero quantity can yield a negative total (store credit / free goods).", ev,
      trace(hitAny("qty_terms", QTY_TERMS, multLc), hitAny("price_terms", PRICE_TERMS, multLc)))
  }
}}

// @@ rule joern-toctou-check-then-write
ruleRan += "joern-toctou-check-then-write"
ctxs.foreach { c => guarded("joern-toctou-check-then-write") {
  val hasCheck = c.cmpCode.nonEmpty
  val hasWrite = c.execHas(SQL_WRITE) || c.execHas(SQL_DELETE) || c.commitCalls > 0
  val cmpLc = c.cmpCode.map(_.toLowerCase)
  val checkOnResource = cmpLc.exists(x => QTY.exists(x.contains))
  if (hasCheck && hasWrite && checkOnResource && !c.guardHas(LOCK)) {
    val ev = c.execCode.headOption.getOrElse("")
    val wrTrace = if (c.execHas(SQL_WRITE)) c.execHit("sql_write_kw", SQL_WRITE)
                  else if (c.execHas(SQL_DELETE)) c.execHit("sql_delete_kw", SQL_DELETE)
                  else "commit_calls"
    add("CWE-362", "high", c.file, c.line, c.name, "joern-toctou-check-then-write",
      "Checks a resource value (e.g. stock/balance) and then mutates it in the same method with no lock or atomic transaction. Concurrent requests can both pass the check before either writes (TOCTOU race), oversubscribing the resource.", ev,
      trace(hitAny("qty_terms", QTY_TERMS, cmpLc), hitAny("price_terms", PRICE_TERMS, cmpLc), wrTrace))
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
  s"""{"methods_seen": $methodsSeen, "methods_threw": $methodsThrew, "findings": ${findings.size}, "rule_state": {$ruleState}, "pack_loaded": ${jstr(packId)}, "pack_source": ${jstr(packSource)}}""")
println(s"JOERN_FINDINGS=${findings.size}")
