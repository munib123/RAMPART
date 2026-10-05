// @@ flow
// Value flow, shared by the rules in 50-60. Three questions a token bag cannot answer:
//
//   resolveConst  what does this expression EVALUATE to, when it is a literal, a module-level
//                 constant of this file, or `module.NAME` of another project module? This is
//                 what defeats config indirection - `app.run(debug=config.DEBUG)` with
//                 `DEBUG = True` in config.py is invisible to a pattern matching `debug=True`.
//   originOf      where does this value COME FROM inside its method? Local def-use, a bounded
//                 number of assignments deep, plus which parameters it reaches.
//   callerArgs    for a parameter, what does each caller pass? One hop of the name-based call
//                 graph, used only to name request input as the source, never to suppress.
//
// Every table is built under table(): a table that throws is empty and named in diag.json, so a
// fault here can cost the rules that read it but never the per-method rules above.

def lc(s: String): String = s.toLowerCase
def moduleStem(file: String): String = file.replace('\\', '/').split('/').last.stripSuffix(".py")
def lineOf(n: AstNode): Int = n.lineNumber.map(_.intValue).getOrElse(-1)

// A constant value and where it is DEFINED - the line a fix changes. `quoted` separates the
// string "True" from the boolean True.
case class Const(value: String, quoted: Boolean, file: String, line: Int, name: String)

// "abc" / 'abc' / r"abc" / b'abc' -> abc (quoted); True / False / None / 5000 -> as written.
// f-strings and triple-quoted strings are not constants.
def literalValue(code: String): Option[(String, Boolean)] = {
  val c = code.trim
  val q = c.indexWhere(ch => ch == '"' || ch == '\'')
  if (q < 0) {
    if (c.nonEmpty && c.forall(ch => ch.isLetterOrDigit || ch == '.' || ch == '-' || ch == '_')) Some((c, false)) else None
  } else {
    val prefix = c.substring(0, q).toLowerCase
    val quote = c.charAt(q)
    val body = c.substring(q)
    if (!prefix.forall("rbu".contains(_)) || body.startsWith(s"$quote$quote$quote")) None
    else if (body.length >= 2 && body.last == quote) Some((body.substring(1, body.length - 1), true))
    else None
  }
}

// Module-level `NAME = <literal>` for every project module, keyed both as "<stem>.NAME" (how
// another module reads it: `config.DEBUG`) and "<file>::NAME" (how its own module reads it).
// A name assigned twice with different values, or ever assigned something computed, is not a
// constant and is left out - better silent than wrong.
val moduleConsts: Map[String, Const] = table("module_consts", Map.empty[String, Const]) {
  val defs = moduleMethods.flatMap { mm =>
    val stem = moduleStem(mm.filename)
    mm.assignment.l.flatMap { a => a.target match {
      case id: IdentNode =>
        val k = a.source match {
          case l: LitNode => literalValue(l.code).map { case (v, q) => Const(v, q, mm.filename, lineOf(a), id.name) }
          case _ => None
        }
        List((stem + "." + id.name, k), (mm.filename + "::" + id.name, k))
      case _ => Nil
    }}
  }
  defs.groupBy(_._1).collect {
    case (key, vs) if vs.forall(_._2.isDefined) && vs.flatMap(_._2).map(_.value).distinct.size == 1 => key -> vs.head._2.get
  }
}

// local assignments of one method: name -> the source expressions assigned to it
val assignCache = scala.collection.mutable.Map[String, Map[String, List[AstNode]]]()
def localAssigns(m: MethodNode): Map[String, List[AstNode]] =
  assignCache.getOrElseUpdate(m.fullName,
    m.assignment.l.flatMap(a => a.target match { case id: IdentNode => List(id.name -> (a.source: AstNode)); case _ => Nil })
      .groupBy(_._1).map { case (k, xs) => k -> xs.map(_._2) })

def resolveConst(e: AstNode, depth: Int = 2): Option[Const] = e match {
  case l: LitNode =>
    literalValue(l.code).map { case (v, q) => Const(v, q, l.method.filename, lineOf(l), "") }
  case i: IdentNode =>
    val m = i.method
    localAssigns(m).get(i.name) match {
      // a local wins over a module constant; it resolves only when it has ONE constant source
      case Some(List(src)) if m.name != "<module>" => if (depth > 0) resolveConst(src, depth - 1) else None
      case Some(_) if m.name != "<module>" => None
      case _ => moduleConsts.get(m.filename + "::" + i.name)
    }
  case c: CallNode if c.name == "<operator>.fieldAccess" =>
    c.argument.l.sortBy(_.argumentIndex) match {
      case List(mod: IdentNode, f: FieldIdNode) => moduleConsts.get(mod.name + "." + f.canonicalName)
      case _ => None
    }
  case _ => None
}

// where a value comes from inside its method: the lower-cased code of the expression and of
// every local assignment it reads (bounded depth), and the parameters it reaches
case class Origin(text: String, params: Set[String])
def originOf(m: MethodNode, e: AstNode, depth: Int = 3): Origin = {
  val params = m.parameter.name.toSet -- Set("self", "cls")
  var text = lc(e.code)
  var ps = Set.empty[String]
  e.ast.isIdentifier.name.l.distinct.foreach { x =>
    if (params.contains(x)) ps += x
    else if (depth > 0) localAssigns(m).getOrElse(x, Nil).foreach { src =>
      val o = originOf(m, src, depth - 1)
      text += "   " + o.text
      ps ++= o.params
    }
  }
  Origin(text, ps)
}
def fromRequest(o: Origin): Boolean = REQUEST_SRC.exists(o.text.contains)

// one hop up: (calling method, argument) for every call site of `m` that passes parameter `p`,
// by keyword or by position (pysrc2cpg numbers both from 1; argument 0 is the receiver)
def callerArgs(m: MethodNode, p: String): List[(MethodNode, AstNode)] = {
  val idx = m.parameter.l.find(_.name == p).map(_.index)
  m.callIn.l.flatMap { c =>
    val args = c.argument.l
    args.find(_.argumentName.contains(p))
      .orElse(idx.flatMap(i => args.find(a => a.argumentName.isEmpty && a.argumentIndex == i)))
      .map(a => (c.method, a: AstNode))
  }
}
// Is the value at `e` (inside `m`) request input - directly, or through a caller's argument?
// Returns the origin text that proves it (so a rule can look for a sanitiser on that path)
// and a human-readable source for the message.
case class Taint(source: String, text: String)
def requestTaint(m: MethodNode, e: AstNode): Option[Taint] = {
  val o = originOf(m, e)
  if (fromRequest(o)) Some(Taint(s"request input read in ${m.name}()", o.text))
  else o.params.toList.sorted.view.flatMap { p =>
    callerArgs(m, p).view.map { case (cm, a) => (cm, originOf(cm, a)) }
      .find { case (_, co) => fromRequest(co) }
      .map { case (cm, co) => Taint(s"request input passed by ${cm.name}() as '$p'", o.text + "   " + co.text) }
  }.headOption
}

// Is the value this node computes USED? pysrc2cpg lowers chained calls into expression blocks
// (`tmp0 = request.args; tmp0.get(...)`), so "parent is a block" alone is not "discarded": the
// last expression of an expression block is the block's value. A block whose parent is the
// method or a control structure is a statement list.
def valueUsed(n: AstNode): Boolean = n.astParent match {
  case b: BlockNode =>
    val last = b.astChildren.l.filterNot(_.isInstanceOf[LocalNode]).maxByOption(_.order).exists(_.id == n.id)
    b.astParent match {
      case _: MethodNode | _: CtrlNode => false
      case _: BlockNode => last && valueUsed(b)
      case _ => last
    }
  case _ => true
}

// Every non-operator call in the analysed methods, by lower-cased name: the call-anchored rules
// look sinks up here instead of each scanning the whole graph. Sorted for a stable output order.
val callsByLowerName: Map[String, List[CallNode]] = table("calls_by_name", Map.empty[String, List[CallNode]]) {
  cpg.call.filterNot(_.name.startsWith("<operator>")).l
    .filter(c => ctxByFullName.contains(c.method.fullName) || c.method.name == "<module>")
    .sortBy(c => (c.method.filename, lineOf(c), c.code))
    .groupBy(c => lc(c.name))
}
// calls whose lower-cased code starts with one of the qualified paths + "(" -> (call, path).
// The last segment of a path is the call's own name, which is how the index is entered.
def callsAt(paths: List[String]): List[(CallNode, String)] =
  paths.groupBy(_.split('.').last).toList.flatMap { case (last, ps) =>
    callsByLowerName.getOrElse(last, Nil).flatMap { c =>
      val code = lc(c.code)
      ps.find(p => code.startsWith(p + "(")).map(p => c -> p)
    }
  }.sortBy { case (c, _) => (c.method.filename, lineOf(c), c.code) }

// the positional argument `i` or the keyword argument named one of `kws`
def argOf(c: CallNode, i: Int, kws: Set[String]): Option[AstNode] = {
  val args = c.argument.l
  args.find(a => a.argumentName.exists(kws.contains))
    .orElse(args.find(a => a.argumentName.isEmpty && a.argumentIndex == i))
}

// report a call-anchored finding with the enclosing method's columns (route, class)
def addAtCall(rule: String, cwe: String, sev: String, c: CallNode, msg: String, ev: String, tr: String): Unit = {
  val m = c.method
  val cx = ctxByFullName.get(m.fullName)
  add(cwe, sev, m.filename, lineOf(c), m.name, rule, msg, ev, tr,
      cx.map(_.route).getOrElse(""), cx.map(_.className).getOrElse(""))
}
// Value-flow findings are reported where the unsafe VALUE is defined: for a module constant that
// is its assignment (config.py), because that is the line a fix changes; for a literal written
// at the call, it is the call itself. One finding per definition, however many sinks read it.
val reportedDefs = scala.collection.mutable.Set[(String, String, Int)]()
def addAtDefinition(rule: String, cwe: String, sev: String, k: Const, sink: CallNode, msg: String, ev: String, tr: String): Unit =
  if (k.name.isEmpty) addAtCall(rule, cwe, sev, sink, msg, ev, tr)
  else if (reportedDefs.add((rule, k.file, k.line)))
    add(cwe, sev, k.file, k.line, "<module>", rule, msg, ev, tr, "", "")

// ---- keyword flows: `call(kw=value)` where value resolves to an unsafe setting -------------
// Entries are "call:keyword=value" (lower-case), compared with == after resolving the argument
// through constants. One finding per call (per definition, for constants).
def kwargFlows(entries: Set[String]): List[(CallNode, List[(String, Const)])] = {
  val callNames = entries.toList.flatMap(e => e.split(":", 2).headOption).distinct
  callNames.flatMap(cn => callsByLowerName.getOrElse(cn, Nil).map(c => cn -> c)).flatMap { case (cn, c) =>
    val hits = c.argument.l.flatMap { a =>
      a.argumentName.toList.flatMap { kw =>
        resolveConst(a).toList.flatMap { k =>
          val key = s"$cn:${lc(kw)}=${lc(k.value.trim)}"
          if (entries.contains(key)) List(key -> k) else Nil
        }
      }
    }
    if (hits.isEmpty) Nil else List(c -> hits)
  }.sortBy { case (c, _) => (c.method.filename, lineOf(c)) }
}
def reportKwargs(rule: String, cwe: String, sev: String, slotName: String, entries: Set[String], what: String): Unit =
  perItem(rule)(kwargFlows(entries)) { case (c, hits) =>
    hits.groupBy { case (_, k) => (k.file, k.line, k.name) }.toList.sortBy(_._1._2).foreach { case (_, hs) =>
      val k = hs.head._2
      val keys = hs.map(_._1).distinct
      addAtDefinition(rule, cwe, sev, k, c,
        s"$what (${keys.map(_.split(":", 2).last).mkString(", ")} in ${c.method.name}() at ${c.method.filename}:${lineOf(c)}${if (k.name.nonEmpty) s", value from ${k.name}" else ""}).",
        san(c.code), trace(keys.map(slotName + "=" + _): _*))
    }
  }
