// Insecure configuration that reaches a sink THROUGH a constant.
//
// Pattern rules match the literal at the call (`debug=True`, `"*"`, `"http://..."`). Real code
// keeps those values in a settings module and passes `config.DEBUG`; the pattern sees an
// attribute, not a value. These rules resolve the argument through module constants across
// files (35_flow resolveConst) and report the DEFINITION - the line a fix changes - naming the
// sink that consumes it.

// @@ rule joern-cors-wildcard
// `resp.headers["Access-Control-Allow-Origin"] = X` (Flask, Django `response[...]`, any
// mapping-style header API) or `headers.set/add(name, X)`, where X resolves to "*", written
// UNCONDITIONALLY (control-dependent on nothing): every response, for every origin. A wildcard
// written under a condition is a configured policy (starlette's CORSMiddleware writes "*" only
// `if allow_all_origins`) and is left to review. The header name is protocol, not vocabulary.
val CORS_HEADER = "access-control-allow-origin"
def isCorsHeader(n: AstNode): Boolean = resolveConst(n).exists(k => k.quoted && lc(k.value) == CORS_HEADER)
def isWildcard(n: AstNode): Option[Const] = resolveConst(n).filter(k => k.quoted && k.value.trim == "*")
perItem("joern-cors-wildcard")({
  // header[name] = value
  val viaIndex = cpg.call.nameExact("<operator>.assignment").l.flatMap { a =>
    val args = a.argument.l.sortBy(_.argumentIndex)
    (args.headOption, args.lift(1)) match {
      case (Some(t: CallNode), Some(v)) if t.name == "<operator>.indexAccess" &&
          t.argument.l.sortBy(_.argumentIndex).lift(1).exists(isCorsHeader) =>
        isWildcard(v).map(k => (a, k))
      case _ => None
    }
  }
  // headers.set(name, value) / headers.add(name, value)
  val viaCall = List("set", "add", "setdefault").flatMap(n => callsByLowerName.getOrElse(n, Nil)).flatMap { c =>
    val args = c.argument.l.filter(_.argumentName.isEmpty).sortBy(_.argumentIndex)
    (args.find(_.argumentIndex == 1), args.find(_.argumentIndex == 2)) match {
      case (Some(h), Some(v)) if isCorsHeader(h) => isWildcard(v).map(k => (c, k))
      case _ => None
    }
  }
  (viaIndex ++ viaCall).filter { case (c, _) => c.controlledBy.isEmpty }
    .sortBy { case (c, _) => (c.method.filename, lineOf(c)) }
}) { case (sink, k) =>
  addAtDefinition("joern-cors-wildcard", "CWE-942", "medium", k, sink,
    s"Sets Access-Control-Allow-Origin to \"*\"${if (k.name.nonEmpty) s" via ${k.name} (defined here, applied in ${sink.method.name}() at ${sink.method.filename}:${lineOf(sink)})" else ""}. Any website may read these responses from a visitor's browser.",
    san(sink.code), if (k.name.nonEmpty) "module_constant=" + k.name else "literal")
}

// @@ rule joern-cleartext-transport
// An outbound HTTP client call whose URL resolves to a plain http:// address that is not
// loopback: tokens, card data and API keys in the request travel unencrypted.
val LOOPBACK = Set("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0")
def httpHost(url: String): Option[String] = {
  val u = url.trim
  if (!lc(u).startsWith("http://")) None
  else Some(lc(u.drop(7).takeWhile(ch => ch != '/' && ch != '?' && ch != '#')).split('@').last.split(':').head)
}
perItem("joern-cleartext-transport")(callsAt(HTTP_CALLS)) { case (c, path) =>
  val urlIdx = if (path.endsWith(".request")) 2 else 1
  argOf(c, urlIdx, Set("url")).flatMap(resolveConst(_)).filter(_.quoted).foreach { k =>
    httpHost(k.value).filter(h => h.nonEmpty && !LOOPBACK.contains(h)).foreach { host =>
      addAtDefinition("joern-cleartext-transport", "CWE-319", "medium", k, c,
        s"Sends an HTTP request in cleartext to http://$host${if (k.name.nonEmpty) s" (${k.name}, used by ${c.method.name}() at ${c.method.filename}:${lineOf(c)})" else ""}. Anything in the request - credentials, API keys, card tokens - can be read or altered on the network. Use https://.",
        san(c.code), trace("http_client_calls=" + path, if (k.name.nonEmpty) "module_constant=" + k.name else "literal"))
    }
  }
}

// @@ rule joern-xxe-parser
// An XML parser configured to resolve external entities / fetch over the network / load DTDs.
// Parsing attacker-influenced XML with it reads local files or reaches internal hosts (XXE).
reportKwargs("joern-xxe-parser", "CWE-611", "high", "xxe_kwargs", XXE_KWARGS,
  "Creates an XML parser with external-entity resolution or network access enabled; parsing untrusted XML with it can read local files or reach internal hosts (XXE)")

// @@ rule joern-debug-exposed
// The application server started with its interactive debugger on. With the Werkzeug debugger,
// any visitor who triggers an exception gets a Python console on the server.
reportKwargs("joern-debug-exposed", "CWE-489", "medium", "debug_kwargs", DEBUG_KWARGS,
  "Starts the application server in debug mode; tracebacks and settings leak to clients and the Werkzeug debugger gives anyone who triggers an error a code-execution console")
