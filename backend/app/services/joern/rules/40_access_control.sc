// Access control: who may touch this record, and which of its fields.

// @@ rule joern-idor-missing-ownership
// A single-record read keyed by a caller-supplied id, with no authorization guard in the method,
// its own decorator, or its class scope (P7). A login-only guard never suppresses; it becomes
// AUTHENTICATED_NOT_AUTHORIZED evidence for the LLM (Fix 2).
perItem("joern-idor-missing-ownership")(ctxs) { c =>
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
}

// @@ rule joern-mass-assignment
// Every field of a caller-supplied mapping written into a record with no allow-list (Fix 6: the
// allow-list is named, never inferred from ' in [' syntax).
perItem("joern-mass-assignment")(ctxs) { c =>
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
}
