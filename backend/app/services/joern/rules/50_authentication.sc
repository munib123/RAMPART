// Authentication: a credential check whose answer is ignored, and credentials baked into code.

// @@ rule joern-ignored-auth-result
// A credential check is called as a STATEMENT: its return value - the only thing that says
// whether the check passed - is thrown away, and the code after it runs either way. A pattern
// matcher sees a well-formed call; the bug is the missing use of its value (`if not ...:`).
// A callee counts as a check when it is a library check named in auth_check_calls
// (check_password_hash, authenticate, ...) or a PROJECT function shaped like one: its name
// carries an auth_check_terms token AND it returns None/False on some path and a computed value
// on another. Checks that RAISE on failure (DRF check_object_permissions) are deliberately not
// in the vocabulary: discarding their None is correct.
def returnCodes(m: MethodNode): List[String] =
  m.ast.isReturn.l.map(r => r.astChildren.l.headOption.map(_.code.trim).getOrElse("None"))
val checkShaped: Map[String, String] = table("check_shaped", Map.empty[String, String]) {
  internalMethods.filter { m =>
    val nm = lc(m.name)
    AUTH_TERMS.exists(nm.contains) && {
      val rets = returnCodes(m)
      rets.exists(r => r == "None" || r == "False") && rets.exists(r => !Set("None", "False", "True").contains(r))
    }
  }.map(m => m.fullName -> AUTH_TERMS.find(lc(m.name).contains).getOrElse("")).toMap
}
perItem("joern-ignored-auth-result")(
  callsByLowerName.values.flatten.filter(c => ctxByFullName.contains(c.method.fullName))
    .filter(c => AUTH_CALL_SET.contains(c.name) || checkShaped.contains(c.methodFullName)).toList
    .sortBy(c => (c.method.filename, lineOf(c)))
) { c =>
  if (!valueUsed(c)) {
    val tr = if (AUTH_CALL_SET.contains(c.name)) "auth_check_calls=" + c.name
             else trace("auth_check_terms=" + checkShaped(c.methodFullName), "returns_none_or_value")
    addAtCall("joern-ignored-auth-result", "CWE-287", "high", c,
      s"Calls ${c.name}() to check credentials but discards its result: nothing tests whether the check passed, so the code after it runs for a wrong password too (authentication bypass). Use the return value (`if not ${c.name}(...): deny`).",
      c.code, tr)
  }
}

// @@ rule joern-hardcoded-credential-compare
// Inbound authentication against a credential that lives in the code: `password == "admin123"`,
// or `password == config.DEFAULT_ADMIN_PASSWORD` with the literal in another module - the
// indirection is what hides it from pattern rules on the comparison. One side names a
// credential (credential_terms) and is not itself a constant; the other side RESOLVES to a
// non-empty string. The value is never echoed into the report.
val EQ_OPS = Set("<operator>.equals", "<operator>.notEquals")
perItem("joern-hardcoded-credential-compare")(
  ctxs.flatMap(_.node.call.l.filter(c => EQ_OPS.contains(c.name)))
) { c =>
  c.argument.l.sortBy(_.argumentIndex) match {
    case List(a, b) =>
      val hits = List((a, b), (b, a)).flatMap { case (subject, other) =>
        val sl = lc(subject.code)
        CRED_TERMS.find(sl.contains).filter(_ => resolveConst(subject).isEmpty).flatMap { term =>
          resolveConst(other).filter(k => k.quoted && k.value.trim.length >= 4).map(k => (term, subject, k))
        }
      }
      hits.headOption.foreach { case (term, subject, k) =>
        val where = if (k.name.nonEmpty) s" (${k.name}, defined at ${k.file}:${k.line})" else ""
        addAtCall("joern-hardcoded-credential-compare", "CWE-798", "high", c,
          s"Compares the credential '${san(subject.code)}' against a hard-coded value$where. Anyone who reads the source or the build knows a working credential, and it cannot be rotated without a deploy.",
          s"${san(subject.code)} == <hard-coded, ${k.value.length} chars>", "credential_terms=" + term + (if (k.name.nonEmpty) ";module_constant" else ""))
      }
    case _ =>
  }
}
