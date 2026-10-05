// Business logic: arithmetic and check-then-act on money and stock.

// @@ rule joern-unchecked-quantity
// A monetary amount computed from a quantity / price with no lower-bound guard. P7 (2): the bound
// may be declared on a project class the method instantiates - a form or serializer field's
// min_value / PositiveIntegerField - not in the view that multiplies.
perItem("joern-unchecked-quantity")(ctxs) { c =>
  val multLc = c.multCode.map(_.toLowerCase)
  val qtyMult = multLc.exists(x => QTY.exists(x.contains))
  val posGuard = c.cmpCode.exists(x => QTY.exists(x.toLowerCase.contains)) || c.guardHas(POS_GUARD) || c.instHas(POS_GUARD)
  if (qtyMult && !posGuard) {
    val ev = c.multCode.headOption.getOrElse("")
    add("CWE-840", "medium", c.file, c.line, c.name, "joern-unchecked-quantity",
      "Computes a monetary amount from a caller-supplied quantity/price with no lower-bound (>0) guard. A negative or zero quantity can yield a negative total (store credit / free goods).", ev,
      trace(hitAny("qty_terms", QTY_TERMS, multLc), hitAny("price_terms", PRICE_TERMS, multLc)), c.route, c.className)
  }
}

// @@ rule joern-toctou-check-then-write
// P7 (1): the write must be CONTROL-DEPENDENT on a comparison over a resource term (the write
// sits in the branch the check decides), and - for an ORM write like `product.save()` - its
// receiver must be the object that was compared (`product.stock >= qty`). A validation bound on
// request input (`if qty <= 0: return`) followed by an unrelated create() is not a race. Raw SQL
// writes have no receiver; they keep the token test.
perItem("joern-toctou-check-then-write")(ctxs) { c =>
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
}
