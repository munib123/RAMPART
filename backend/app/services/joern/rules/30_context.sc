// @@ context
// Everything the rules need about the project, computed ONCE. Design: the locator rules are
// INTRAPROCEDURAL heuristics plus the method's class scope. pysrc2cpg's interprocedural edges are
// name-based (dynamic dispatch / unresolved receivers become external stubs), so the call graph
// is only used where a wrong edge costs a report flag or one hop of evidence, never a guard.
//
// Cost model: every table here is one pass over the graph; per method, the AST and the contained
// calls are materialised once and filtered in Scala. The July code re-ran a full traversal per
// method per slot (Fix 7), and the P7 route hops rebuilt a set per method - both quadratic.

val moduleMethods: List[MethodNode] = cpg.method.nameExact("<module>").l
// Fix 7 (part 1): the module-scope call table, keyed by filename, lowercased once.
val moduleCallsByFile: Map[String, List[String]] =
  moduleMethods.map(mm => mm.filename -> mm.call.code.l.map(c => norm(c.toLowerCase)))
    .groupBy(_._1).map { case (f, xs) => f -> xs.flatMap(_._2) }

// ---- P7 (2): class scope ------------------------------------------------------------------
// pysrc2cpg puts a class body into a `<body>` method of the TYPE_DECL and lists the class's
// methods and attributes as MEMBERs. A guard that lives on the class - DRF permission_classes,
// a LoginRequiredMixin base, get_queryset() scoping every get_object() - is invisible to a
// per-method token bag; these tables make it visible.
// The class BODY is the TYPE_DECL's `<body>` method (plus nested classes such as Meta); the
// class's real methods are separate METHOD nodes and their bodies are NOT class scope - one
// method's ownership check must never silence IDOR in a sibling method.
// A decorated method is lowered INTO the class body as `name = deco(def name(...))`; that call
// guards one method (the per-method decoAnchor test below), never the whole class, so it is
// kept out of the class text and out of the class identifiers.
val projectTypeDecls: List[TypeDeclNode] = cpg.typeDecl.isExternal(false).nameNot("<.*>\\d*").l
def isDecoLowering(n: AstNode): Boolean =
  n.inAst.isCall.exists(_.code.contains("(def ")) || (n match {
    case c: CallNode => c.code.contains("(def ")
    case _ => false
  })
def classBodyNodes(t: TypeDeclNode): List[AstNode] =
  t.ast.filter { n =>
    n.inAst.isMethod.headOption.forall(m => m.name == "<body>" || m.name.startsWith("<")) && !isDecoLowering(n)
  }.l
val classBodies: List[(TypeDeclNode, List[AstNode])] = projectTypeDecls.map(t => t -> classBodyNodes(t))
// class name -> normalised lower-cased text of its body (member initialisers, nested Meta,
// decorators) plus the names of its bases
val classTextByName: Map[String, String] = classBodies.map { case (t, body) =>
  val calls = body.collect { case c: CallNode => c.code }
  val ids   = body.collect { case i: IdentNode => i.name }
  t.name -> norm((calls ++ ids ++ t.inheritsFromTypeFullName.l).mkString("   ").toLowerCase)
}.toMap
// class name -> the identifiers its body names (the classes listed in permission_classes = [...])
val classIdentsByName: Map[String, Set[String]] =
  classBodies.map { case (t, body) => t.name -> body.collect { case i: IdentNode => i.name }.toSet }.toMap
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
  else projectTypeDecls.filter(_.member.name.exists(OBJPERM_HOOKS.contains)).map(_.name).toSet
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
val routedNames: Set[String] = moduleMethods.flatMap(_.ast.isCall.l)
  .filter(c => c.method.name == "<module>")            // module level only, not nested defs
  .filter(c => ROUTE_MARKERS.exists(norm(c.code.toLowerCase).contains))
  .flatMap(c => c.ast.isFieldIdentifier.canonicalName.l ++ c.ast.isIdentifier.name.l)
  .toSet
val hasRouteMarkers: Boolean = routedNames.nonEmpty
def routedDirect(m: MethodNode): Boolean =
  routedNames.contains(m.name) ||
  m.typeDecl.headOption.exists(t => routedNames.contains(t.name)) ||
  moduleCallsByFile.getOrElse(m.filename, Nil).exists(c => c.contains("(def " + m.name.toLowerCase + "(") && ROUTE_MARKERS.exists(c.contains))
val internalMethods: List[MethodNode] = cpg.method.isExternal(false).l
// method fullName -> fullNames of the methods that call it; one callIn traversal per method
val callersOf: Map[String, Set[String]] =
  internalMethods.groupMapReduce(_.fullName)(_.callIn.method.fullName.toSet)(_ ++ _)
val routedMethods: Set[String] = {
  val direct = internalMethods.filter(routedDirect).map(_.fullName).toSet
  // two hops of callIn: what a routed method calls is reachable too
  def calledFrom(from: Set[String]) = callersOf.collect { case (f, cs) if cs.exists(from.contains) => f }.toSet
  val hop1 = calledFrom(direct)
  val hop2 = calledFrom(direct ++ hop1)
  direct ++ hop1 ++ hop2
}

// Everything a rule needs about one method, computed in ONE traversal. Rules iterate `ctxs`,
// so in server mode a rule that fails to compile leaves the contexts intact for the others.
case class Ctx(node: MethodNode, fullName: String, name: String, file: String, line: Int, params: List[String],
               signalText: String, guardText: String, execCode: List[String],
               hasAuthz: Boolean, authnNote: String,
               readCalls: List[String], setattrCalls: List[String],
               iterCalls: Int, multCode: List[String], cmpCode: List[String], commitCalls: Int,
               // P7
               className: String, classText: String, instText: String,
               scopedRead: Boolean, classAuthz: String,
               ctlWrites: List[(String, String)],   // (write code, controlling comparison code)
               route: String) {
  private val execUpper = execCode.map(_.toUpperCase)
  def blobHas(toks: List[String])  = toks.exists(signalText.contains)
  def guardHas(toks: List[String]) = toks.exists(guardText.contains)
  // P7 (2): a guard may live on the enclosing class (permission_classes, mixins) ...
  def classHas(toks: List[String]) = toks.exists(classText.contains)
  // ... or in a project class the method instantiates (a form/serializer field's min_value)
  def instHas(toks: List[String])  = toks.exists(instText.contains)
  def execHas(kws: List[String]) = kws.exists(kw => execUpper.exists(_.contains(kw)))
  def execHit(slotName: String, kws: List[String]): String =
    kws.find(kw => execUpper.exists(_.contains(kw))).map(v => slotName + "=" + v).getOrElse("")
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

// Fix 8: every .name(s) / .code(s) / .filename(s) accessor treats s as a REGEX. Every literal
// match uses nameExact or a Scala Set; the one deliberate regex is the nameNot() that excludes
// synthetic scopes. Fix 4: name matchers are full-match regexes - pysrc2cpg names synthetic
// scopes "<lambda>0", "<comprehension>1", "<module>", so the pattern carries the index digits.
def ctx(m: MethodNode): Ctx = {
  val name = m.name
  val file = m.filename
  // Fix 3: two channels, and the split is load-bearing.
  //   signalText  calls + literals + identifiers - what the method DOES and mentions
  //   guardText   calls + identifiers only       - what the method does; NO literals
  // Guards are tested against guardText, so a docstring or a string constant can never satisfy
  // one. Nodes are joined with a 3-space separator so a token cannot match ACROSS two nodes.
  val SEP = "   "
  val nodes  = m.ast.l                                // one AST walk feeds all three lists
  val calls  = nodes.collect { case c: CallNode => c.code }
  val idents = nodes.collect { case i: IdentNode => i.name }
  val lits   = nodes.collect { case l: LitNode => l.code }
  val signalText = norm((calls ++ lits ++ idents).mkString(SEP).toLowerCase)
  val guardText  = norm((calls ++ idents).mkString(SEP).toLowerCase)
  val mcalls = m.call.l                               // one CONTAINS walk feeds every name filter
  def named(names: Set[String]): List[CallNode] = mcalls.filter(c => names.contains(c.name))
  // Fix 7 (part 2): match the decorator lowering EXACTLY as "(def <name>(", not contains(name).
  // pysrc2cpg lowers @deco def view(...) to `view = deco(def view(...))` at module scope.
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
  val instText  = mcalls.map(_.name).distinct.flatMap(classTextByName.get).mkString("   ")
  val scopedRead = SCOPED_SET.nonEmpty && named(SCOPED_SET).nonEmpty
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
  val execCalls  = named(EXEC_SET)
  val execWrites = execCalls.filter(c => (SQL_WRITE ++ SQL_DELETE).exists(c.code.toUpperCase.contains))
  val ormWrites  = named(COMMIT_SET)
  val ctlWrites: List[(String, String)] = (execWrites ++ ormWrites).flatMap { w =>
    w.controlledBy.isCall.ast.isCall.filter(c => CMP_OPS.contains(c.name)).code.l.distinct.map(c => w.code -> c)
  }

  // P7 (3)
  val route = if (!hasRouteMarkers) "unknown" else if (routedMethods.contains(m.fullName)) "yes" else "no"

  Ctx(
    node = m, fullName = m.fullName,
    name = name, file = file, line = m.lineNumber.getOrElse(-1),
    params = m.parameter.name.l.map(_.toLowerCase),
    signalText = signalText, guardText = guardText,
    // call_name slots reach Set.contains ONLY - exact string equality, never a regex.
    execCode = execCalls.map(_.code),
    hasAuthz = hasAuthz, authnNote = authnNote,
    readCalls = named(READ_SET).map(_.code),
    setattrCalls = named(DYN_SET).map(_.code),
    iterCalls = named(ITER_SET).size,
    // the operators are rule SHAPE, not vocabulary: they stay here
    multCode = mcalls.filter(_.name == "<operator>.multiplication").map(_.code),
    cmpCode = mcalls.filter(c => CMP_OPS.contains(c.name)).map(_.code),
    commitCalls = ormWrites.size,
    className = className, classText = classText, instText = instText,
    scopedRead = scopedRead, classAuthz = classAuthz, ctlWrites = ctlWrites, route = route,
  )
}

val ctxs: List[Ctx] = cpg.method.isExternal(false).nameNot("<.*>\\d*", "__.*__", ".*<.*>.*").l.flatMap { m =>
  methodsSeen += 1
  try Some(ctx(m)) catch { case NonFatal(e) => methodsThrew += 1; None }
}
// the analysed methods by fullName: the call-anchored rules (50+) report through this, so they
// see exactly the methods the per-method rules see and inherit their route / class columns
val ctxByFullName: Map[String, Ctx] = ctxs.map(c => c.fullName -> c).toMap
