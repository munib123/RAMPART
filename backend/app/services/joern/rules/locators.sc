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
//   cwe \t severity \t file \t line \t method \t rule \t message \t evidence \t pack_tag \t slot_trace \t route \t class
// Columns 9-10 are provenance (P5): which pack, and which slot=value made the rule fire.
// Column 11 (P7) is route reachability: yes | no | unknown. Reported, never a gate.
// Column 12 (P8) is the enclosing class ("" for a module-level function).
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
def add(cwe: String, sev: String, file: String, line: Int, meth: String, rule: String, msg: String, ev: String, trace: String, route: String = "", cls: String = ""): Unit =
  findings += List(cwe, sev, file, line.toString, meth, rule, san(msg), san(ev), packTag, san(trace), route, cls).mkString("\t")
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
// Representation fix (P6, found on the DEV split): pysrc2cpg renders keyword arguments and
// assignments with spaces around the equals sign - `get_object_or_404(Order, pk = order_id,
// user = request.user)` - while every pack author writes tokens the way source and docs spell
// them: `user=request.user`, `min_value=1`, `fields=[`. Both the method text and every pack
// value are normalised to the compact form, so the two spellings are one token. `==`, `!=`,
// `>=`, `<=` contain no " = " and are untouched.
def norm(s: String): String = s.replace(" = ", "=")
def slot(name: String): List[String] = pack("slots")(name)("values").arr.map(v => norm(v.str)).toList.distinct

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
// P7 slots: class scope and routes. Empty in _base; framework packs fill them.
val SCOPED_READ = slot("scoped_read_calls")      // reads that go through the class queryset hook
val QS_HOOKS    = slot("queryset_hooks")         // class methods whose body scopes those reads
val OBJPERM_HOOKS = slot("object_permission_hooks") // a class defining one is object-level auth
val ROUTE_MARKERS = slot("route_markers")        // module-level calls that register a route

// @@ context
// Fix 7 (part 1): the module-scope call table is computed ONCE. The July code ran
// cpg.method.name("<module>").filter(...).call.code.l inside the per-method loop - a full
// graph traversal plus materialisation per method, quadratic, and the first thing that dies
// on a 50k-LOC repo. Keyed by filename; values lowercased once.
val moduleCallsByFile: Map[String, List[String]] =
  cpg.method.nameExact("<module>").l
    .map(mm => mm.filename -> mm.call.code.l.map(c => norm(c.toLowerCase)))
    .groupBy(_._1).map { case (f, xs) => f -> xs.flatMap(_._2) }

// ---- P7 (2): class scope ------------------------------------------------------------------
// pysrc2cpg puts a class body into a `<body>` method of the TYPE_DECL and lists the class's
// methods and attributes as MEMBERs. A guard that lives on the class - DRF permission_classes,
// a LoginRequiredMixin base, get_queryset() scoping every get_object() - is invisible to a
// per-method token bag; these tables make it visible. Computed once for every project class.
type TypeDeclNode = io.shiftleft.codepropertygraph.generated.nodes.TypeDecl
val projectTypeDecls: List[TypeDeclNode] = cpg.typeDecl.isExternal(false).nameNot("<.*>\\d*").l
// class name -> normalised lower-cased text of its body (member initialisers, nested Meta,
// decorators) plus the names of its bases; and the identifiers the body names (the classes
// listed in permission_classes = [...])
// The class BODY is the TYPE_DECL's `<body>` method (plus nested classes such as Meta); the
// class's real methods are separate METHOD nodes and their bodies are NOT class scope - one
// method's ownership check must never silence IDOR in a sibling method.
// A decorated method is lowered INTO the class body as `name = deco(def name(...))`; that call
// guards one method (the per-method decoAnchor test below), never the whole class, so it is
// kept out of the class text and out of the class identifiers.
def isDecoLowering(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Boolean =
  n.inAst.isCall.exists(_.code.contains("(def ")) || (n match {
    case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.code.contains("(def ")
    case _ => false
  })
def classBodyNodes(t: TypeDeclNode) =
  t.ast.filter { n =>
    n.inAst.isMethod.headOption.forall(m => m.name == "<body>" || m.name.startsWith("<")) && !isDecoLowering(n)
  }
val classTextByName: Map[String, String] = projectTypeDecls.map { t =>
  val body  = classBodyNodes(t).isCall.code.l ++ classBodyNodes(t).isIdentifier.name.l
  val bases = t.inheritsFromTypeFullName.l
  t.name -> norm((body ++ bases).mkString("   ").toLowerCase)
}.toMap
val classIdentsByName: Map[String, Set[String]] =
  projectTypeDecls.map(t => t.name -> classBodyNodes(t).isIdentifier.name.toSet).toMap
// class name -> the decorator lowerings in its body, lower-cased + normalised, so a class
// method's own decorator (`@check_owner def a(...)`) counts for `a` exactly as a module-level
// decorator does for a module-level function
val classDecoCallsByName: Map[String, List[String]] = projectTypeDecls.map { t =>
  t.name -> t.ast.isCall.code.l.filter(_.contains("(def ")).map(c => norm(c.toLowerCase))
}.toMap
val CMP_OPS = Set("<operator>.greaterThan", "<operator>.greaterEqualsThan",
                  "<operator>.lessThan", "<operator>.lessEqualsThan")
// classes that define an object-level permission hook (DRF has_object_permission)
val objectPermClasses: Set[String] =
  if (OBJPERM_HOOKS.isEmpty) Set.empty
  else projectTypeDecls.filter(_.member.name.exists(OBJPERM_HOOKS.contains)).name.toSet
// class name -> guard text of its queryset hooks (get_queryset), which scope every scoped read
val querysetTextByClass: Map[String, String] =
  if (QS_HOOKS.isEmpty) Map.empty
  else cpg.method.isExternal(false).nameExact(QS_HOOKS: _*).l.flatMap { hm =>
    hm.typeDecl.headOption.map { t =>
      t.name -> norm((hm.ast.isCall.code.l ++ hm.ast.isIdentifier.name.l).mkString("   ").toLowerCase)
    }
  }.groupBy(_._1).map { case (k, xs) => k -> xs.map(_._2).mkString("   ") }

// ---- P7 (3): route reachability ------------------------------------------------------------
// A module-level call whose code contains a route marker registers a route; every name it
// references is routed (`path("x/", views.order_detail)`, `router.register("y", api.OrderViewSet)`,
// `.as_view()`), and so is a function wrapped by a marker decorator (`@app.route(...)`).
// A routed CLASS routes all its methods. Then two hops of the (name-based) call graph.
// Reported on every finding, never used to gate a rule.
val routedNames: Set[String] = cpg.method.nameExact("<module>").ast.isCall.l
  .filter(c => c.method.name == "<module>")            // module level only, not nested defs
  .filter(c => ROUTE_MARKERS.exists(norm(c.code.toLowerCase).contains))
  .flatMap(c => c.ast.isFieldIdentifier.canonicalName.l ++ c.ast.isIdentifier.name.l)
  .toSet
val hasRouteMarkers: Boolean = routedNames.nonEmpty
def routedDirect(m: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean =
  routedNames.contains(m.name) ||
  m.typeDecl.headOption.exists(t => routedNames.contains(t.name)) ||
  moduleCallsByFile.getOrElse(m.filename, Nil).exists(c => c.contains("(def " + m.name.toLowerCase + "(") && ROUTE_MARKERS.exists(c.contains))
val routedMethods: Set[String] = {
  val direct = cpg.method.isExternal(false).l.filter(routedDirect).map(_.fullName).toSet
  // two hops of callIn: what a routed method calls is reachable too
  val hop1 = cpg.method.isExternal(false).l.filter(_.callIn.method.fullName.l.exists(direct.contains)).map(_.fullName).toSet
  val hop2 = cpg.method.isExternal(false).l.filter(_.callIn.method.fullName.l.exists((direct ++ hop1).contains)).map(_.fullName).toSet
  direct ++ hop1 ++ hop2
}

// Everything a rule needs about one method, computed in ONE traversal. Rules iterate `ctxs`,
// so in server mode a rule that fails to compile leaves the contexts intact for the others.
case class Ctx(name: String, file: String, line: Int, params: List[String],
               signalText: String, guardText: String, execCode: List[String],
               hasAuthz: Boolean, authnNote: String,
               readCalls: List[String], setattrCalls: List[String],
               iterCalls: Int, multCode: List[String], cmpCode: List[String], commitCalls: Int,
               // P7
               className: String, classText: String, instText: String,
               scopedRead: Boolean, classAuthz: String,
               ctlWrites: List[(String, String)],   // (write code, controlling comparison code)
               route: String) {
  def blobHas(toks: List[String])  = toks.exists(signalText.contains)
  def guardHas(toks: List[String]) = toks.exists(guardText.contains)
  // P7 (2): a guard may live on the enclosing class (permission_classes, mixins) ...
  def classHas(toks: List[String]) = toks.exists(classText.contains)
  // ... or in a project class the method instantiates (a form/serializer field's min_value)
  def instHas(toks: List[String])  = toks.exists(instText.contains)
  def execHas(kws: List[String]) = kws.exists(kw => execCode.exists(_.toUpperCase.contains(kw)))
  def execHit(slotName: String, kws: List[String]): String =
    kws.find(kw => execCode.exists(_.toUpperCase.contains(kw))).map(v => slotName + "=" + v).getOrElse("")
}

// P7 (1): the receiver of `x.y.save()` is `x`; of `product.stock` is `product`. Crude on
// purpose - the identity test only has to hold within one method's own spelling.
// `cart.product.save()` -> "cart.product": the dotted chain in front of the last call.
def receiverOf(code: String): String = {
  val c = code.trim.toLowerCase
  val paren = c.indexOf('(')
  val head = if (paren > 0) c.substring(0, paren) else c
  val dot = head.lastIndexOf('.')
  if (dot > 0) head.substring(0, dot).trim else ""
}
// receivers of every `a.b.field` in a comparison whose field mentions a resource term:
// "cart.product.stock >= q" -> Set("cart.product")
val fieldRef = """((?:[a-z_][a-z0-9_]*\.)+)([a-z_][a-z0-9_]*)""".r
def resourceReceivers(cmp: String): Set[String] =
  fieldRef.findAllMatchIn(cmp.toLowerCase).filter(mm => QTY.exists(mm.group(2).contains))
    .map(_.group(1).stripSuffix(".")).toSet
// the write's receiver is the compared object, or a suffix/prefix of it (`self.cart.product`)
def sameReceiver(write: String, cmpReceivers: Set[String]): Boolean = {
  val w = receiverOf(write)
  w.nonEmpty && cmpReceivers.exists(r => r == w || r.endsWith("." + w) || w.endsWith("." + r))
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
  val signalText = norm((calls ++ m.ast.isLiteral.code.l ++ idents).mkString(SEP).toLowerCase)
  val guardText  = norm((calls ++ idents).mkString(SEP).toLowerCase)
  // Fix 7 (part 2): match the decorator lowering EXACTLY as "(def <name>(", not contains(name).
  // pysrc2cpg lowers @deco def view(...) to `view = deco(def view(...))` at module scope. With
  // contains(), `get_note_extra = check_owner(def get_note_extra(...))` credited the shorter,
  // undecorated sibling get_note with a guard it does not have.
  val decoAnchor  = "(def " + name.toLowerCase + "("
  // P7 (2): the enclosing class, if the method is a method. The module's own pseudo-class is
  // not a class; only project TYPE_DECLs count.
  val className = m.typeDecl.headOption.map(_.name).filter(classTextByName.contains).getOrElse("")
  // this method's OWN decorator lowering: at module level for a function, in the class body
  // for a method (matched as "(def <name>(", never by contains(name) - fix 7)
  val moduleCalls = (moduleCallsByFile.getOrElse(file, Nil) ++ classDecoCallsByName.getOrElse(className, Nil))
    .filter(_.contains(decoAnchor))
  val classText = classTextByName.getOrElse(className, "")
  // project classes this method instantiates (AddToCartForm(request.POST) -> the form's body)
  val instText  = m.call.name.l.distinct.flatMap(classTextByName.get).mkString("   ")
  val scopedRead = SCOPED_READ.nonEmpty && m.call.nameExact(SCOPED_READ: _*).nonEmpty
  // which class-scope guard, if any, authorises this method's read
  val classAuthz: String = {
    val onClass = AUTHZ.find(classText.contains).map("class:" + _)
    val viaQueryset = if (!scopedRead) None
      else AUTHZ.find(querysetTextByClass.getOrElse(className, "").contains).map("queryset_hook:" + _)
    val viaObjPerm = if (!scopedRead) None
      else classIdentsByName.getOrElse(className, Set.empty).intersect(objectPermClasses).headOption.map("object_permission:" + _)
    (onClass orElse viaQueryset orElse viaObjPerm).getOrElse("")
  }
  val hasAuthz = AUTHZ.exists(guardText.contains) || moduleCalls.exists(c => AUTHZ.exists(c.contains)) || classAuthz.nonEmpty
  val authnTok = (AUTHN_ONLY.filter(guardText.contains) ++
                  AUTHN_ONLY.filter(a => moduleCalls.exists(_.contains(a))) ++
                  AUTHN_ONLY.filter(classText.contains)).distinct
  val authnNote = if (authnTok.nonEmpty && !hasAuthz) s" AUTHENTICATED_NOT_AUTHORIZED(${authnTok.mkString(",")})" else ""

  // P7 (1): every write paired with the comparisons it is CONTROL-DEPENDENT on. A comparison
  // hidden inside `a or b` is reached through the controlling node's AST.
  val execWrites = m.call.nameExact(EXEC_CALLS: _*).l.filter(c => (SQL_WRITE ++ SQL_DELETE).exists(c.code.toUpperCase.contains))
  val ormWrites  = m.call.nameExact(COMMIT_CALLS: _*).l
  val ctlWrites: List[(String, String)] = (execWrites ++ ormWrites).flatMap { w =>
    w.controlledBy.isCall.ast.isCall.filter(c => CMP_OPS.contains(c.name)).code.l.distinct.map(c => w.code -> c)
  }

  // P7 (3)
  val route = if (!hasRouteMarkers) "unknown" else if (routedMethods.contains(m.fullName)) "yes" else "no"

  Ctx(
    name = name, file = file, line = m.lineNumber.getOrElse(-1),
    params = m.parameter.name.l.map(_.toLowerCase),
    signalText = signalText, guardText = guardText,
    // call_name slots reach nameExact ONLY - exact string equality, never a regex.
    execCode = m.call.nameExact(EXEC_CALLS: _*).code.l,
    hasAuthz = hasAuthz, authnNote = authnNote,
    readCalls = m.call.nameExact((READ_CALLS ++ SCOPED_READ).distinct: _*).code.l,
    setattrCalls = m.call.nameExact(DYN_WRITE: _*).code.l,
    iterCalls = m.call.nameExact(ITER_CALLS: _*).size,
    // the operators are rule SHAPE, not vocabulary: they stay here
    multCode = m.call.nameExact("<operator>.multiplication").code.l,
    cmpCode = m.call.nameExact("<operator>.greaterThan", "<operator>.greaterEqualsThan",
                               "<operator>.lessThan", "<operator>.lessEqualsThan").code.l,
    commitCalls = m.call.nameExact(COMMIT_CALLS: _*).size,
    className = className, classText = classText, instText = instText,
    scopedRead = scopedRead, classAuthz = classAuthz, ctlWrites = ctlWrites, route = route,
  )
}

val ctxs: List[Ctx] = cpg.method.isExternal(false).nameNot("<.*>\\d*", "__.*__", ".*<.*>.*").l.flatMap { m =>
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
      s"Reads a record by the caller-supplied id '${idName}' with no ownership or authorization check in the method${if (c.className.nonEmpty) " or on its class " + c.className else ""}. If this record is user-owned, any authenticated user can read another user's data (IDOR).${c.authnNote}", ev,
      trace(idTrace, readTrace, if (c.scopedRead) "scoped_read" else ""), c.route, c.className)
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
      trace(sigTrace, wrTrace), c.route, c.className)
  }
}}

// @@ rule joern-unchecked-quantity
ruleRan += "joern-unchecked-quantity"
ctxs.foreach { c => guarded("joern-unchecked-quantity") {
  val multLc = c.multCode.map(_.toLowerCase)
  val qtyMult = multLc.exists(x => QTY.exists(x.contains))
  // P7 (2): the bound may be declared on a project class the method instantiates - a form or
  // serializer field's min_value / PositiveIntegerField - not in the view that multiplies.
  val posGuard = c.cmpCode.exists(x => QTY.exists(x.toLowerCase.contains)) || c.guardHas(POS_GUARD) || c.instHas(POS_GUARD)
  if (qtyMult && !posGuard) {
    val ev = c.multCode.headOption.getOrElse("")
    add("CWE-840", "medium", c.file, c.line, c.name, "joern-unchecked-quantity",
      "Computes a monetary amount from a caller-supplied quantity/price with no lower-bound (>0) guard. A negative or zero quantity can yield a negative total (store credit / free goods).", ev,
      trace(hitAny("qty_terms", QTY_TERMS, multLc), hitAny("price_terms", PRICE_TERMS, multLc)), c.route, c.className)
  }
}}

// @@ rule joern-toctou-check-then-write
ruleRan += "joern-toctou-check-then-write"
ctxs.foreach { c => guarded("joern-toctou-check-then-write") {
  // P7 (1): the July rule accepted ANY comparison plus ANY write in any order. Now the write
  // must be CONTROL-DEPENDENT on a comparison over a resource term (the write sits in the
  // branch the check decides), and - for an ORM write like `product.save()` - its receiver
  // must be the object that was compared (`product.stock >= qty`). A validation bound on
  // request input (`if qty <= 0: return`) followed by an unrelated create() is no longer a
  // race. Raw SQL writes have no receiver; they keep the token test.
  val isExecWrite = (w: String) => (SQL_WRITE ++ SQL_DELETE).exists(w.toUpperCase.contains) && EXEC_CALLS.exists(e => w.contains(e + "("))
  val pairs = c.ctlWrites.filter { case (w, cmp) =>
    val cmpLc = cmp.toLowerCase
    QTY.exists(cmpLc.contains) && (isExecWrite(w) || sameReceiver(w, resourceReceivers(cmpLc)))
  }
  if (pairs.nonEmpty && !c.guardHas(LOCK)) {
    val (w, cmp) = pairs.head
    val cmpLc = cmp.toLowerCase
    val wrTrace = if (isExecWrite(w)) { val t = c.execHit("sql_write_kw", SQL_WRITE); if (t.isEmpty) c.execHit("sql_delete_kw", SQL_DELETE) else t }
                  else COMMIT_CALLS.find(cc => w.contains("." + cc + "(")).map("commit_calls=" + _).getOrElse("commit_calls")
    add("CWE-362", "high", c.file, c.line, c.name, "joern-toctou-check-then-write",
      s"Checks a resource value (${san(cmp)}) and then writes it in the branch that check decides, with no lock or atomic transaction. Concurrent requests can both pass the check before either writes (TOCTOU race), oversubscribing the resource.", w,
      trace(hitAny("qty_terms", QTY_TERMS, List(cmpLc)), hitAny("price_terms", PRICE_TERMS, List(cmpLc)), wrTrace, "controlled_by"), c.route, c.className)
  }
}}

// @@ reverify
// P8 (O3): when scan.py asks about ONE method, describe what the graph sees in it after a fix -
// which guard tokens are present (and where: method / class / instantiated class), which sinks
// remain, and its route flag. Together with the rule outcome this answers the O3 question
// precisely: did the locator go quiet because a guard appeared, or because the sink vanished,
// or not at all. A no-op when __REVERIFY_METHOD__ is empty (every ordinary scan).
val reverifyFile   = "__REVERIFY_FILE__"
val reverifyMethod = "__REVERIFY_METHOD__"
val reverifyClass  = "__REVERIFY_CLASS__"      // "" = any class / module level
val reverifyOut    = "__REVERIFY_OUT__"
if (reverifyMethod.nonEmpty) {
  def fwd(s: String) = s.replace('\\', '/')
  def jlist(xs: List[String]) = xs.map(jstr).mkString("[", ",", "]")
  val hits = ctxs.filter(c => fwd(c.file) == reverifyFile && c.name == reverifyMethod &&
                              (reverifyClass.isEmpty || c.className == reverifyClass))
  val methodsJson = hits.map { c =>
    val where = (label: String, text: String, toks: List[String]) => toks.filter(text.contains).map(t => label + ":" + t)
    val authz = where("method", c.guardText, AUTHZ) ++ where("class", c.classText, AUTHZ) ++
                (if (c.classAuthz.nonEmpty) List(c.classAuthz) else Nil)
    val authn = where("method", c.guardText, AUTHN_ONLY) ++ where("class", c.classText, AUTHN_ONLY)
    val lock  = where("method", c.guardText, LOCK)
    val allow = where("method", c.guardText, ALLOWLIST)
    val pos   = where("method", c.guardText, POS_GUARD) ++ where("instantiated_class", c.instText, POS_GUARD) ++
                (if (c.cmpCode.exists(x => QTY.exists(x.toLowerCase.contains))) List("method:comparison_on_quantity") else Nil)
    val execReads  = c.execCode.count(x => SQL_READ.exists(x.toUpperCase.contains))
    val execWrites = c.execCode.count(x => (SQL_WRITE ++ SQL_DELETE).exists(x.toUpperCase.contains))
    s"""{"name": ${jstr(c.name)}, "line": ${c.line}, "class": ${jstr(c.className)}, "route": ${jstr(c.route)},
       |  "guards": {"authz": ${jlist(authz)}, "authn": ${jlist(authn)}, "lock": ${jlist(lock)}, "allowlist": ${jlist(allow)}, "positive": ${jlist(pos)}},
       |  "sinks": {"reads": ${c.readCalls.size}, "exec_reads": $execReads, "exec_writes": $execWrites, "dyn_writes": ${c.setattrCalls.size},
       |            "iter_calls": ${c.iterCalls}, "mult": ${c.multCode.size}, "cmp": ${c.cmpCode.size}, "orm_writes": ${c.commitCalls}, "ctl_writes": ${c.ctlWrites.size}}}""".stripMargin
  }
  os.write.over(os.Path(reverifyOut),
    s"""{"file": ${jstr(reverifyFile)}, "method": ${jstr(reverifyMethod)}, "found": ${hits.nonEmpty}, "methods": [${methodsJson.mkString(",")}]}""")
}

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
