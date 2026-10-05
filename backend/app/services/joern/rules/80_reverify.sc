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
  // sink counts of the call-anchored rules; a count that cannot be computed reads -1, never 0
  def count(body: => Int): Int = try body catch { case NonFatal(_) => -1 }
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
    val url   = where("method", c.guardText, URL_GUARD)
    val pathG = where("method", c.guardText, PATH_GUARD)
    val execReads  = c.execCode.count(x => SQL_READ.exists(x.toUpperCase.contains))
    val execWrites = c.execCode.count(x => (SQL_WRITE ++ SQL_DELETE).exists(x.toUpperCase.contains))
    val mine = (cs: List[CallNode]) => cs.count(_.method.fullName == c.fullName)
    val httpCalls = count(mine(callsAt(HTTP_CALLS).map(_._1)))
    val fileCalls = count(mine(callsAt(FILE_CALLS).map(_._1)))
    val authDiscarded = count(c.node.call.l.count(x =>
      (AUTH_CALL_SET.contains(x.name) || checkShaped.contains(x.methodFullName)) && !valueUsed(x)))
    val credCompares = count(c.node.call.l.count(x => (x.name == "<operator>.equals" || x.name == "<operator>.notEquals") &&
      x.argument.l.exists(a => CRED_TERMS.exists(lc(a.code).contains)) &&
      x.argument.l.exists(a => resolveConst(a).exists(k => k.quoted && k.value.trim.length >= 4))))
    s"""{"name": ${jstr(c.name)}, "line": ${c.line}, "class": ${jstr(c.className)}, "route": ${jstr(c.route)},
       |  "guards": {"authz": ${jlist(authz)}, "authn": ${jlist(authn)}, "lock": ${jlist(lock)}, "allowlist": ${jlist(allow)}, "positive": ${jlist(pos)}, "url": ${jlist(url)}, "path": ${jlist(pathG)}},
       |  "sinks": {"reads": ${c.readCalls.size}, "exec_reads": $execReads, "exec_writes": $execWrites, "dyn_writes": ${c.setattrCalls.size},
       |            "iter_calls": ${c.iterCalls}, "mult": ${c.multCode.size}, "cmp": ${c.cmpCode.size}, "orm_writes": ${c.commitCalls}, "ctl_writes": ${c.ctlWrites.size},
       |            "http_calls": $httpCalls, "file_calls": $fileCalls, "auth_discarded": $authDiscarded, "cred_compares": $credCompares}}""".stripMargin
  }
  os.write.over(os.Path(reverifyOut),
    s"""{"file": ${jstr(reverifyFile)}, "method": ${jstr(reverifyMethod)}, "found": ${hits.nonEmpty}, "methods": [${methodsJson.mkString(",")}]}""")
}
