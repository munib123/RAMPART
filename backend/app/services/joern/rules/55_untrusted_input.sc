// Untrusted input reaching a sensitive sink, across a function boundary.
//
// Both rules follow the value from the sink argument back through local assignments to request
// input, in the same method or one caller up (`webhook()` reads request.form and passes it to
// `notify_webhook(callback_url)`, which fetches it). Intraprocedural pattern rules lose exactly
// that hop. A sanitiser anywhere on the path - in the sink's method or in the origin text the
// caller contributed - suppresses the finding.

// @@ rule joern-ssrf-request-url
// An outbound HTTP request whose URL is request input with no host / scheme allow-list. A URL
// that RESOLVES to a constant is not SSRF (the cleartext rule looks at those).
perItem("joern-ssrf-request-url")(callsAt(HTTP_CALLS)) { case (c, path) =>
  val urlIdx = if (path.endsWith(".request")) 2 else 1          // requests.request("GET", url)
  argOf(c, urlIdx, Set("url")).filter(u => resolveConst(u).isEmpty).foreach { u =>
    val m = c.method
    val guardHere = ctxByFullName.get(m.fullName).exists(_.guardHas(URL_GUARD))
    requestTaint(m, u).filterNot(t => guardHere || URL_GUARD.exists(t.text.contains)).foreach { t =>
      addAtCall("joern-ssrf-request-url", "CWE-918", "high", c,
        s"Sends a server-side HTTP request to a URL built from ${t.source}, with no allow-list on its host or scheme. An attacker can make the server call internal services or cloud metadata endpoints (SSRF).",
        c.code, trace("http_client_calls=" + path, hit("request_sources", REQUEST_SRC, t.text)))
    }
  }
}

// @@ rule joern-path-traversal
// A file read / write / delete whose path is request input with no sanitiser or containment
// check. os.path.join(BASE, name) is not a guard: an absolute or ../ name escapes BASE.
perItem("joern-path-traversal")(callsAt(FILE_CALLS)) { case (c, path) =>
  argOf(c, 1, Set("file", "path", "filename", "path_or_file")).filter(p => resolveConst(p).isEmpty).foreach { p =>
    val m = c.method
    val guardHere = ctxByFullName.get(m.fullName).exists(_.guardHas(PATH_GUARD))
    requestTaint(m, p).filterNot(t => guardHere || PATH_GUARD.exists(t.text.contains)).foreach { t =>
      addAtCall("joern-path-traversal", "CWE-22", "high", c,
        s"Opens a file path built from ${t.source}, with no sanitiser (secure_filename / basename) or containment check (realpath + startswith / commonpath). A name like ../../etc/passwd or an absolute path escapes the intended directory (path traversal).",
        c.code, trace("file_sink_calls=" + path, hit("request_sources", REQUEST_SRC, t.text)))
    }
  }
}
