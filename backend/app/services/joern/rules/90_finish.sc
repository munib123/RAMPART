// @@ finish
// The always-write contract: findings.tsv exists even when clean, so scan.py can tell "clean"
// from "the locators never ran". diag.json says which rules ran and which threw; in server
// mode a rule whose section failed to COMPILE never adds itself to ruleRan, so it reports
// "not_run" here and scan.py upgrades that to "compile_error" from the /query-sync flag.
// table_errors names any shared flow table (35_flow) that threw and was replaced by an empty one.
os.write.over(os.Path(outFile), findings.mkString("\n"))
val ruleState = RULES.map { r =>
  val st = if (!ruleRan.contains(r)) "not_run" else if (ruleErrors(r) == 0) "ok" else "threw"
  s"${jstr(r)}: {\"state\": ${jstr(st)}, \"errors\": ${ruleErrors(r)}, \"first_error\": ${jstr(ruleFirst.getOrElse(r, ""))}}"
}.mkString(", ")
val tableState = tableErrors.toList.sorted.map { case (t, e) => s"${jstr(t)}: ${jstr(e)}" }.mkString(", ")
os.write.over(os.Path(diagFile),
  s"""{"methods_seen": $methodsSeen, "methods_threw": $methodsThrew, "findings": ${findings.size}, "rule_state": {$ruleState}, "table_errors": {$tableState}, "pack_loaded": ${jstr(packId)}, "pack_source": ${jstr(packSource)}}""")
println(s"JOERN_FINDINGS=${findings.size}")
