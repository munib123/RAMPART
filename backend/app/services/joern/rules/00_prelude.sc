// RAMPART - Joern/CPG locator rules for the SAST-blind bugs that pattern scanners (semgrep /
// bandit) cannot see. Joern LOCATES candidates structurally; it does not prove them. The LLM
// verification step downstream confirms or rejects each one.
//
// ONE PROGRAM, SEVERAL FILES. scan.py concatenates rules/*.sc in file-name order and renders the
// placeholders below. Each file holds one or more `// @@ <kind> [<name>]` sections:
//
//   00_prelude.sc           placeholders, the findings buffer, helpers, the rule registry
//   10_import.sc            importCode - builds the CPG
//   20_vocab.sc             reads the vocabulary pack (DATA) into token lists
//   30_context.sc           per-method facts (Ctx), class scope, route reachability
//   35_flow.sc              value flow: module constants across files, local def-use, callers
//   40_access_control.sc    IDOR, mass assignment
//   45_business_logic.sc    unchecked quantity, TOCTOU
//   50_authentication.sc    ignored auth result, hard-coded credential comparison
//   55_untrusted_input.sc   SSRF, path traversal
//   60_insecure_config.sc   CORS wildcard, cleartext transport, XXE parser, debug mode
//   80_reverify.sc          O3 re-verification of one method (P8)
//   90_finish.sc            the always-write contract: findings.tsv + diag.json
//
// TWO EXECUTION MODES, ONE PROGRAM. Script mode (`joern --script`) runs the concatenation. Server
// mode (P3) sends each section as its own /query-sync request to a long-lived REPL, so a compile
// error in one rule costs that rule and nothing else. The REPL keeps vals across requests, which
// is what lets sections share state. A section may only depend on sections ABOVE it.
//
// Placeholders (substituted by scan.py, Scala-escaped): __INPUT_DIR__, __OUT_FILE__,
// __DIAG_FILE__, __PROJECT__, __PACK_FILE__, __BASE_PACK_FILE__, __PACK_TAG__, __REVERIFY_*__.
// Output is TSV:
//   cwe \t severity \t file \t line \t method \t rule \t message \t evidence \t pack_tag \t slot_trace \t route \t class
// Columns 9-10 are provenance (P5): which pack, and which slot=value made the rule fire.
// Column 11 (P7) is route reachability: yes | no | unknown ("" when the finding is a module-level
// definition). Reported, never a gate. Column 12 (P8) is the enclosing class.
//
// VOCABULARY IS DATA (P5). These files hold rule SHAPES and nothing framework-specific. Every token
// list comes from a JSON vocabulary pack (vocab/packs/*.json) that scan.py validates against
// vocab/schema.json. A pack value only ever reaches String.contains / startsWith / endsWith, ==,
// Set membership or nameExact; nothing from a pack is compiled, and no accessor that treats its
// argument as a regex ever sees a pack value. The Scala is frozen and hashed; the pack is what
// varies per target - so `--pack A` vs `--pack B` on one testbed is a clean ablation.

// @@ prelude
import scala.collection.mutable.ListBuffer
import scala.util.control.NonFatal
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Block => BlockNode, Call => CallNode,
  ControlStructure => CtrlNode, FieldIdentifier => FieldIdNode, Identifier => IdentNode,
  Literal => LitNode, Local => LocalNode, Method => MethodNode, TypeDecl => TypeDeclNode}

val inputDir     = "__INPUT_DIR__"
val outFile      = "__OUT_FILE__"
val diagFile     = "__DIAG_FILE__"
val projName     = "__PROJECT__"
val packFile     = "__PACK_FILE__"
val basePackFile = "__BASE_PACK_FILE__"
val packTag      = "__PACK_TAG__"        // "<pack_id>@<sha256[:12]>", column 9 of every finding

// Every rule this program can run, in section order. finish reports a state for each one, so a
// rule whose section never ran (a compile error in server mode) reads "not_run", never "clean".
val RULES = List(
  "joern-idor-missing-ownership", "joern-mass-assignment",                       // 40 access control
  "joern-unchecked-quantity", "joern-toctou-check-then-write",                   // 45 business logic
  "joern-ignored-auth-result", "joern-hardcoded-credential-compare",             // 50 authentication
  "joern-ssrf-request-url", "joern-path-traversal",                              // 55 untrusted input
  "joern-cors-wildcard", "joern-cleartext-transport", "joern-xxe-parser",        // 60 insecure config
  "joern-debug-exposed")

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
def jstr(s: String): String = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

// Fix 1: a rule that THROWS must never look like a rule that found nothing. Every rule body is
// wrapped; a throw is recorded per rule and the run continues. scan.py reads diag.json after
// the run, so "ok" and "threw" are distinguishable. Before this, one throw anywhere skipped
// the os.write at the end and the whole target reported UNSCANNED.
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
// The one way a rule runs: mark it ran, collect its items under the guard (a failing collection
// is a throw of THIS rule, not of the program), then judge each item under the guard.
def perItem[T](rule: String)(items: => Iterable[T])(judge: T => Unit): Unit = {
  ruleRan += rule
  var xs: Iterable[T] = Nil
  guarded(rule) { xs = items }
  xs.foreach(x => guarded(rule)(judge(x)))
}

// Shared tables (35_flow) are built under their own guard: a table that throws is empty and
// named in diag.json, so it can cost the rules that read it but never the four that do not.
val tableErrors = scala.collection.mutable.Map[String, String]()
def table[T](name: String, empty: => T)(build: => T): T =
  try build catch { case NonFatal(e) =>
    tableErrors(name) = san(s"${e.getClass.getSimpleName}: ${Option(e.getMessage).getOrElse("")}").take(200)
    empty
  }
