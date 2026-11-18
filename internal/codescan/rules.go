package codescan

// Built-in rules follow the declarative taint-rule shape used by open-source
// SAST tooling: sources (untrusted input), sinks (dangerous operations),
// sanitizers (neutralizing operations) and a category/CWE/severity metadata
// block. Rules are data, never code: adding a language means adding a table,
// not a new parser.
//
// arg_index is 1-based and only applies to sinks. Zero (or omitted) means any
// argument. SQL sinks pin arg_index=1 so parameterized calls whose user data is
// supplied as a later bound parameter are not misreported.

func p(kind string, names ...string) PatternSpec {
	return PatternSpec{Kind: kind, Names: names}
}

func pArg(kind string, arg int, names ...string) PatternSpec {
	return PatternSpec{Kind: kind, Names: names, ArgIndex: arg}
}

func rule(langs []string, id, category, cwe, severity, confidence, title, message string, sources, sinks, sanitizers []PatternSpec, safe []string) RuleSpec {
	return RuleSpec{
		ID: id, Languages: langs, Category: category, CWE: cwe,
		Severity: severity, Confidence: confidence, Title: title, Message: message,
		Sources: sources, Sinks: sinks, Sanitizers: sanitizers, SafeCalls: safe,
	}
}

func builtinRules() []RuleSpec {
	out := []RuleSpec{}
	out = append(out, phpRules()...)
	out = append(out, csharpRules()...)
	out = append(out, pythonRules()...)
	out = append(out, javaScriptRules()...)
	out = append(out, javaRules()...)
	out = append(out, goRules()...)
	return out
}

func phpRules() []RuleSpec {
	langs := []string{"php"}
	sources := []PatternSpec{
		p("access", "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER", "$_ENV", "$GLOBALS"),
		p("call", "$request->input", "$request->query", "$request->get", "$request->post", "$request->file", "Request::input", "filter_input", "file_get_contents"),
	}
	sqlSanitizers := []PatternSpec{p("call", "intval", "floatval", "->quote", "PDO::quote", "mysqli_real_escape_string", "addslashes", "filter_var", "bindParam", "bindValue", "prepare")}
	commonSanitizers := []PatternSpec{p("call", "htmlspecialchars", "htmlentities", "intval", "floatval", "addslashes", "escapeshellarg", "escapeshellcmd", "urlencode", "rawurlencode", "filter_var", "basename", "realpath", "strip_tags", "hash", "md5", "sha1")}
	return []RuleSpec{
		rule(langs, "php.sql.query", "sql", "CWE-89", "high", "high", "PHP SQL 注入", "请求数据流入 SQL 执行接口，未见参数绑定或转义。", sources,
			[]PatternSpec{pArg("call", 1, "mysql_query", "mysqli_query", "pg_query", "sqlite_query", "->query", "->exec", "->raw", "->whereRaw", "->selectRaw", "DB::select", "DB::raw", "DB::statement")}, sqlSanitizers,
			[]string{"prepare", "bindParam", "bindValue", "->quote", "PDO::quote", "mysqli_real_escape_string"}),
		rule(langs, "php.command.exec", "command", "CWE-78", "high", "high", "PHP 命令注入", "请求数据流入进程执行接口。", sources,
			[]PatternSpec{p("call", "exec", "shell_exec", "system", "passthru", "popen", "proc_open", "pcntl_exec", "->command")},
			[]PatternSpec{p("call", "escapeshellarg", "escapeshellcmd", "intval", "basename")}, nil),
		rule(langs, "php.code_exec.eval", "code_exec", "CWE-94", "high", "high", "PHP 代码执行", "请求数据流入动态代码求值或文件包含。", sources,
			[]PatternSpec{p("call", "eval", "assert", "create_function", "preg_replace", "include", "require", "include_once", "require_once", "call_user_func_array")},
			[]PatternSpec{p("call", "intval", "basename", "realpath")}, nil),
		rule(langs, "php.deserialization.unserialize", "deserialization", "CWE-502", "high", "high", "PHP 不安全反序列化", "请求数据流入反序列化接口。", sources,
			[]PatternSpec{pArg("call", 1, "unserialize")}, nil, nil),
		rule(langs, "php.path.file_access", "path", "CWE-22", "high", "medium", "PHP 路径穿越", "请求数据流入文件系统接口。", sources,
			[]PatternSpec{p("call", "fopen", "readfile", "file", "scandir", "unlink", "rmdir", "file_put_contents", "move_uploaded_file", "is_file", "file_exists")}, commonSanitizers, nil),
		rule(langs, "php.ssrf.request", "ssrf", "CWE-918", "high", "medium", "PHP 服务端请求伪造", "请求数据流出站请求接口。", sources,
			[]PatternSpec{p("call", "curl_exec", "Requests::get", "Http::get", "file_get_contents")},
			[]PatternSpec{p("call", "urlencode", "filter_var", "parse_url")}, nil),
		rule(langs, "php.xss.output", "xss", "CWE-79", "medium", "medium", "PHP 反射型 XSS", "请求数据未转义直接写入响应。", sources,
			[]PatternSpec{p("statement", "echo", "print", "printf", "die", "exit")}, commonSanitizers, nil),
		rule(langs, "php.xxe.parse", "xxe", "CWE-611", "high", "medium", "PHP XML 外部实体", "请求数据流入 XML 解析接口。", sources,
			[]PatternSpec{p("call", "simplexml_load_string", "simplexml_load_file", "->loadXML", "DOMDocument::loadXML")}, nil, nil),
		rule(langs, "php.upload.move", "upload", "CWE-434", "medium", "medium", "PHP 文件上传", "上传数据流入文件写入接口，扩展名/内容校验未建模。", []PatternSpec{p("access", "$_FILES")},
			[]PatternSpec{p("call", "move_uploaded_file")}, []PatternSpec{p("call", "basename", "realpath", "pathinfo")}, nil),
		rule(langs, "php.ldap.search", "ldap", "CWE-90", "medium", "medium", "PHP LDAP 注入", "请求数据流入 LDAP 查询接口。", sources,
			[]PatternSpec{p("call", "ldap_search", "ldap_list", "ldap_read")}, []PatternSpec{p("call", "ldap_escape")}, nil),
		rule(langs, "php.redirect.header", "redirect", "CWE-601", "medium", "medium", "PHP 开放重定向", "请求数据流入 Location 头或重定向接口，目标域名未建模校验。", sources,
			[]PatternSpec{pArg("call", 1, "header", "Redirect::to", "redirect()->to", "redirect()->away")}, nil, nil),
		rule(langs, "php.xpath.query", "xpath", "CWE-643", "high", "medium", "PHP XPath 注入", "请求数据流入 XPath 查询表达式。", sources,
			[]PatternSpec{p("call", "DOMXPath.query", "DOMXPath.evaluate", "->xpath", "xpath->query", "xpath->evaluate", "simplexml->xpath")}, nil, nil),
	}
}

func csharpRules() []RuleSpec {
	langs := []string{"csharp"}
	sources := []PatternSpec{
		p("access", "Request.Query", "Request.QueryString", "Request.Form", "Request.Params", "Request.Cookies", "Request.Headers", "Request.Body", "HttpContext.Request", "Context.Request", "routeData"),
		p("call", "Request.Form.TryGetValue", "Request.ReadFormAsync", "Console.ReadLine", "Request.Cookies.TryGetValue"),
	}
	sqlSafe := []string{"SqlParameter", "Parameters.AddWithValue", "Parameters.Add", "Prepare", "FromSqlInterpolated", "ExecuteSqlInterpolated"}
	return []RuleSpec{
		rule(langs, "csharp.sql.command", "sql", "CWE-89", "high", "high", ".NET SQL 注入", "请求数据流入 CommandText 或 SQL 执行接口。", sources,
			[]PatternSpec{pArg("call", 1, "SqlCommand", "DbCommand", "ExecuteSqlRaw", "FromSqlRaw", "ExecuteNonQuery", "ExecuteReader", "ExecuteScalar", "SqlDataAdapter"),
				p("assign", "CommandText", ".CommandText", "cmd.CommandText", "command.CommandText")},
			[]PatternSpec{p("call", "SqlParameter", "Parameters.AddWithValue", "Parameters.Add", "int.Parse", "Convert.ToInt32", "HtmlEncode")}, sqlSafe),
		rule(langs, "csharp.command.process", "command", "CWE-78", "high", "high", ".NET 命令注入", "请求数据流入进程启动接口。", sources,
			[]PatternSpec{p("call", "Process.Start", "ProcessStartInfo", "Process.StartInfo")},
			[]PatternSpec{p("call", "Path.GetFileName", "int.Parse", "Convert.ToInt32")}, nil),
		rule(langs, "csharp.deserialization.formatter", "deserialization", "CWE-502", "high", "high", ".NET 不安全反序列化", "请求数据流入已知不安全格式化器。", sources,
			[]PatternSpec{p("call", "Deserialize", "BinaryFormatter.Deserialize", "LosFormatter.Deserialize", "ObjectStateFormatter.Deserialize", "NetDataContractSerializer.ReadObject", "XmlSerializer.Deserialize")}, nil, nil),
		rule(langs, "csharp.path.file", "path", "CWE-22", "high", "medium", ".NET 路径穿越", "请求数据流入文件系统接口。", sources,
			[]PatternSpec{p("call", "File.ReadAllText", "File.ReadAllBytes", "File.Open", "File.OpenRead", "File.Delete", "File.WriteAllText", "FileStream", "Directory.GetFiles", "PhysicalFile")},
			[]PatternSpec{p("call", "Path.GetFileName", "Path.GetFullPath", "HtmlEncode")}, nil),
		rule(langs, "csharp.ssrf.http", "ssrf", "CWE-918", "high", "medium", ".NET 服务端请求伪造", "请求数据流入站 HTTP 客户端。", sources,
			[]PatternSpec{p("call", "HttpClient.GetAsync", "HttpClient.GetStringAsync", "HttpClient.PostAsync", "HttpClient.SendAsync", "WebRequest.Create", "WebClient.DownloadString", "WebClient.DownloadData")},
			[]PatternSpec{p("call", "Uri.EscapeDataString", "UrlEncoder.Default.Encode")}, nil),
		rule(langs, "csharp.xss.response", "xss", "CWE-79", "medium", "medium", ".NET 反射型 XSS", "请求数据未编码写入响应。", sources,
			[]PatternSpec{p("call", "Response.Write", "Response.WriteAsync", "Html.Raw", "WriteAsync", "Write")},
			[]PatternSpec{p("call", "HtmlEncode", "HtmlAttributeEncode", "JavaScriptStringEncode", "WebUtility.HtmlEncode", "AntiXssEncoder.HtmlEncode")}, nil),
		rule(langs, "csharp.xxe.xml", "xxe", "CWE-611", "high", "medium", ".NET XML 外部实体", "请求数据流入 XML 解析接口；DtdProcessing 配置未建模。", sources,
			[]PatternSpec{p("call", "XmlReader.Create", "XmlDocument.LoadXml", "XDocument.Parse", "XmlDocument.Load")}, nil, nil),
		rule(langs, "csharp.code_exec.script", "code_exec", "CWE-94", "high", "medium", ".NET 动态代码执行", "请求数据流入脚本求值或动态编译接口。", sources,
			[]PatternSpec{p("call", "CSharpScript.EvaluateAsync", "CompileAssemblyFromSource", "Eval")}, nil, nil),
		rule(langs, "csharp.upload.save", "upload", "CWE-434", "medium", "medium", ".NET 文件上传", "上传文件写入服务端路径，扩展名/内容校验未建模。", sources,
			[]PatternSpec{p("call", "SaveAs", "PostedFile.SaveAs", "CopyToAsync", "File.Copy")},
			[]PatternSpec{p("call", "Path.GetFileName", "GetExtension")}, nil),
		rule(langs, "csharp.redirect.response", "redirect", "CWE-601", "medium", "medium", ".NET 开放重定向", "请求数据流入重定向接口，目标域名未建模校验。", sources,
			[]PatternSpec{pArg("call", 1, "Redirect", "RedirectPermanent", "RedirectToRoute", "LocalRedirect", "Response.Redirect")}, nil, nil),
	}
}

func pythonRules() []RuleSpec {
	langs := []string{"python"}
	sources := []PatternSpec{
		p("access", "request.args", "request.form", "request.values", "request.json", "request.data", "request.GET", "request.POST", "request.headers", "request.cookies", "request.query_params", "sys.argv", "flask.request"),
		p("call", "input", "request.get_json", "request.args.get", "request.form.get", "request.GET.get", "request.POST.get"),
	}
	return []RuleSpec{
		rule(langs, "python.sql.execute", "sql", "CWE-89", "high", "high", "Python SQL 注入", "请求数据进入查询字符串构造。", sources,
			[]PatternSpec{pArg("call", 1, "cursor.execute", "execute", "executemany", "executescript", "session.execute", "raw", "objects.raw", "text", "connection.execute")},
			[]PatternSpec{p("call", "int", "float", "cursor.mogrify", "sqlalchemy.text", "quote")}, []string{"mogrify", "parameterize"}),
		rule(langs, "python.command.subprocess", "command", "CWE-78", "high", "high", "Python 命令注入", "请求数据流入进程执行接口。", sources,
			[]PatternSpec{p("call", "os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output", "commands.getoutput")},
			[]PatternSpec{p("call", "shlex.quote", "int", "float", "pipes.quote")}, nil),
		rule(langs, "python.code_exec.eval", "code_exec", "CWE-94", "high", "high", "Python 代码执行", "请求数据流入动态求值接口。", sources,
			[]PatternSpec{pArg("call", 1, "eval", "exec", "compile")}, nil, nil),
		rule(langs, "python.deserialization.pickle", "deserialization", "CWE-502", "high", "high", "Python 不安全反序列化", "请求数据流入 pickle/yaml/marshal 反序列化。", sources,
			[]PatternSpec{p("call", "pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load", "marshal.loads", "jsonpickle.decode", "dill.loads")}, nil, nil),
		rule(langs, "python.path.file", "path", "CWE-22", "high", "medium", "Python 路径穿越", "请求数据流入文件系统接口。", sources,
			[]PatternSpec{p("call", "open", "os.remove", "os.unlink", "shutil.copy", "send_file", "send_from_directory", "FileResponse")},
			[]PatternSpec{p("call", "secure_filename", "os.path.basename", "html.escape", "int")}, nil),
		rule(langs, "python.ssrf.http", "ssrf", "CWE-918", "high", "medium", "Python 服务端请求伪造", "请求数据流入站 HTTP 客户端。", sources,
			[]PatternSpec{p("call", "requests.get", "requests.post", "requests.request", "urllib.request.urlopen", "httpx.get", "httpx.post")},
			[]PatternSpec{p("call", "urllib.parse.quote", "urlencode")}, nil),
		rule(langs, "python.xss.response", "xss", "CWE-79", "medium", "medium", "Python 反射型 XSS", "请求数据未转义进入 HTML 输出。", sources,
			[]PatternSpec{p("call", "render_template_string", "Markup", "make_response", "Response")},
			[]PatternSpec{p("call", "escape", "html.escape", "markupsafe.escape", "bleach.clean")}, nil),
		rule(langs, "python.template.render", "template", "CWE-1336", "high", "medium", "Python 模板注入", "请求数据作为模板源码编译。", sources,
			[]PatternSpec{p("call", "Template", "from_string", "Environment.from_string")}, nil, nil),
		rule(langs, "python.xxe.parse", "xxe", "CWE-611", "high", "medium", "Python XML 外部实体", "请求数据流入 XML 解析接口。", sources,
			[]PatternSpec{p("call", "etree.fromstring", "etree.parse", "lxml.etree.fromstring", "ElementTree.fromstring")}, nil, nil),
		rule(langs, "python.redirect.response", "redirect", "CWE-601", "medium", "medium", "Python 开放重定向", "请求数据流入重定向接口，目标域名未建模校验。", sources,
			[]PatternSpec{pArg("call", 1, "redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse")}, nil, nil),
	}
}

func javaScriptRules() []RuleSpec {
	langs := []string{"javascript", "typescript"}
	sources := []PatternSpec{
		p("access", "req.query", "req.body", "req.params", "req.headers", "req.cookies", "request.query", "request.body", "ctx.query", "ctx.request.body", "ctx.params", "window.location", "location.search", "document.URL", "process.argv"),
		p("call", "req.param", "req.get", "request.input", "URLSearchParams", "cookies.get"),
	}
	return []RuleSpec{
		rule(langs, "js.sql.query", "sql", "CWE-89", "high", "high", "JS/TS SQL 注入", "请求数据进入查询字符串构造。", sources,
			[]PatternSpec{pArg("call", 1, "query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe", "knex.raw", "sequelize.query", "connection.query", "pool.query")},
			[]PatternSpec{p("call", "escape", "sqlstring.escape", "mysql.escape", "parseInt", "Number")}, []string{"prepare", "bind", "escape"}),
		rule(langs, "js.command.exec", "command", "CWE-78", "high", "high", "JS/TS 命令注入", "请求数据流入子进程接口。", sources,
			[]PatternSpec{p("call", "exec", "execSync", "spawn", "spawnSync", "child_process.exec", "child_process.execSync")},
			[]PatternSpec{p("call", "escapeShellArg", "parseInt", "Number")}, nil),
		rule(langs, "js.code_exec.eval", "code_exec", "CWE-94", "high", "high", "JS/TS 代码执行", "请求数据流入动态求值接口。", sources,
			[]PatternSpec{pArg("call", 1, "eval", "Function", "vm.runInThisContext", "vm.runInNewContext", "setTimeout", "setInterval")}, nil, nil),
		rule(langs, "js.deserialization.unserialize", "deserialization", "CWE-502", "high", "medium", "JS/TS 不安全反序列化", "请求数据流入反序列化接口。", sources,
			[]PatternSpec{p("call", "unserialize", "deserialize", "serialize-javascript.deserialize")}, nil, nil),
		rule(langs, "js.path.file", "path", "CWE-22", "high", "medium", "JS/TS 路径穿越", "请求数据流入文件系统接口。", sources,
			[]PatternSpec{p("call", "readFile", "readFileSync", "createReadStream", "writeFile", "writeFileSync", "unlink", "res.sendFile", "sendFile")},
			[]PatternSpec{p("call", "path.basename", "basename", "encodeURIComponent", "parseInt")}, nil),
		rule(langs, "js.ssrf.fetch", "ssrf", "CWE-918", "high", "medium", "JS/TS 服务端请求伪造", "请求数据流入站 HTTP 客户端。", sources,
			[]PatternSpec{p("call", "fetch", "axios.get", "axios.post", "axios.request", "http.get", "http.request", "got", "request", "superagent.get")},
			[]PatternSpec{p("call", "encodeURIComponent", "encodeURI", "URL")}, nil),
		rule(langs, "js.xss.response", "xss", "CWE-79", "medium", "medium", "JS/TS 反射型 XSS", "请求数据未转义写入响应或 DOM。", sources,
			[]PatternSpec{p("call", "res.send", "res.write", "res.end", "document.write", "res.json"),
				p("assign", "innerHTML", "outerHTML", "dangerouslySetInnerHTML")},
			[]PatternSpec{p("call", "escapeHtml", "escape", "DOMPurify.sanitize", "encodeURIComponent", "validator.escape")}, nil),
		rule(langs, "js.template.render", "template", "CWE-1336", "high", "medium", "JS/TS 模板注入", "请求数据作为模板源码编译。", sources,
			[]PatternSpec{p("call", "ejs.render", "pug.render", "handlebars.compile", "nunjucks.renderString", "mustache.render")}, nil, nil),
		rule(langs, "js.redirect.res", "redirect", "CWE-601", "medium", "medium", "JS/TS 开放重定向", "请求数据流入重定向接口，目标域名未建模校验。", sources,
			[]PatternSpec{pArg("call", 1, "res.redirect", "response.redirect", "ctx.redirect")}, nil, nil),
	}
}

func javaRules() []RuleSpec {
	langs := []string{"java"}
	sources := []PatternSpec{
		p("call", "getParameter", "getParameterValues", "getParameterMap", "getQueryString", "getHeader", "getHeaders", "getInputStream", "getReader", "getCookies", "getPart", "getPathInfo"),
		p("access", "request.body", "request.params", "RequestBody", "RequestParam", "PathVariable", "RequestHeader", "CookieValue"),
	}
	return []RuleSpec{
		rule(langs, "java.sql.statement", "sql", "CWE-89", "high", "medium", "Java SQL 注入", "请求数据进入动态 SQL 构造。", sources,
			[]PatternSpec{pArg("call", 1, "executeQuery", "executeUpdate", "execute", "createNativeQuery", "createQuery", "queryForObject", "queryForList", "jdbcTemplate.query", "jdbcTemplate.update", "nativeQuery")},
			[]PatternSpec{p("call", "setString", "setParameter", "setInt", "Integer.parseInt", "HtmlUtils.htmlEscape")}, []string{"prepareStatement", "setString", "setParameter", "CriteriaBuilder"}),
		rule(langs, "java.command.runtime", "command", "CWE-78", "high", "high", "Java 命令注入", "请求数据流入进程执行接口。", sources,
			[]PatternSpec{p("call", "exec", "Runtime.exec", "ProcessBuilder", "ProcessBuilder.start", "getRuntime().exec")},
			[]PatternSpec{p("call", "Integer.parseInt", "URLEncoder.encode")}, nil),
		rule(langs, "java.deserialization.readobject", "deserialization", "CWE-502", "high", "medium", "Java 不安全反序列化", "请求数据流入对象反序列化接口。", sources,
			[]PatternSpec{p("call", "readObject", "readUnshared", "XMLDecoder.readObject", "ObjectMapper.readValue"),
				p("receiver", "readObject", "readUnshared", "readValue")}, nil, nil),
		rule(langs, "java.path.file", "path", "CWE-22", "high", "medium", "Java 路径穿越", "请求数据流入文件系统接口。", sources,
			[]PatternSpec{p("call", "FileInputStream", "FileOutputStream", "Files.readAllBytes", "Files.newInputStream", "Files.delete", "RandomAccessFile")},
			[]PatternSpec{p("call", "Paths.normalize", "FilenameUtils.getName", "Integer.parseInt")}, nil),
		rule(langs, "java.ssrf.url", "ssrf", "CWE-918", "high", "medium", "Java 服务端请求伪造", "请求数据流入站请求接口。", sources,
			[]PatternSpec{p("call", "URL", "openConnection", "openStream", "getForObject", "exchange", "WebClient.get", "HttpClient.send")},
			[]PatternSpec{p("call", "URLEncoder.encode", "UriComponentsBuilder.fromUriString")}, nil),
		rule(langs, "java.xss.writer", "xss", "CWE-79", "medium", "medium", "Java 反射型 XSS", "请求数据未编码写入响应。", sources,
			[]PatternSpec{p("call", "print", "println", "write", "getWriter().print")},
			[]PatternSpec{p("call", "HtmlUtils.htmlEscape", "escapeHtml4", "encodeForHTML", "URLEncoder.encode")}, nil),
		rule(langs, "java.xxe.parse", "xxe", "CWE-611", "high", "medium", "Java XML 外部实体", "请求数据流入 XML 解析接口。", sources,
			[]PatternSpec{p("call", "DocumentBuilder.parse", "SAXParser.parse", "SAXReader.read", "XMLInputFactory.createXMLStreamReader", "Unmarshaller.unmarshal")}, nil, nil),
		rule(langs, "java.template.spel", "template", "CWE-1336", "high", "medium", "Java 表达式注入", "请求数据作为 SpEL/模板表达式求值。", sources,
			[]PatternSpec{p("call", "parseExpression", "SpelExpressionParser.parseExpression", "Template.process")}, nil, nil),
		rule(langs, "java.redirect.response", "redirect", "CWE-601", "medium", "medium", "Java 开放重定向", "请求数据流入重定向目标（sendRedirect 或 RedirectView 目标参数）。", sources,
			[]PatternSpec{pArg("call", 1, "sendRedirect", "RedirectView")}, nil, nil),
		rule(langs, "java.xpath.evaluate", "xpath", "CWE-643", "high", "medium", "Java XPath 注入", "请求数据流入 XPath 表达式编译或求值。", sources,
			[]PatternSpec{pArg("call", 1, "XPath.compile", "xpath.compile", "evaluate", "XPathExpression.evaluate", "xpath.evaluate")}, nil, nil),
	}
}

func goRules() []RuleSpec {
	langs := []string{"go"}
	sources := []PatternSpec{
		p("call", "FormValue", "PostFormValue", "Query", "URL.Query", "FormFile", "Get", "Param", "PostForm", "QueryArray", "ReadAll"),
		p("access", "r.URL", "r.Body", "r.Form", "r.Host", "req.URL", "c.Query", "c.Param", "os.Args"),
	}
	return []RuleSpec{
		rule(langs, "go.sql.query", "sql", "CWE-89", "high", "medium", "Go SQL 注入", "请求数据进入查询字符串构造。", sources,
			[]PatternSpec{pArg("call", 1, "db.Query", "db.Exec", "db.QueryRow", "Query", "Exec", "QueryRow", "QueryContext", "ExecContext", "Raw", "Where")},
			[]PatternSpec{p("call", "strconv.Atoi", "url.QueryEscape", "sql.Named")}, []string{"Prepare", "PrepareContext", "sql.Named"}),
		rule(langs, "go.command.exec", "command", "CWE-78", "high", "high", "Go 命令注入", "请求数据流入进程执行接口。", sources,
			[]PatternSpec{p("call", "exec.Command", "exec.CommandContext", "syscall.Exec")},
			[]PatternSpec{p("call", "strconv.Atoi", "filepath.Base")}, nil),
		rule(langs, "go.path.file", "path", "CWE-22", "high", "medium", "Go 路径穿越", "请求数据流入文件系统接口。", sources,
			[]PatternSpec{p("call", "os.Open", "os.ReadFile", "os.WriteFile", "os.Remove", "ioutil.ReadFile", "http.ServeFile")},
			[]PatternSpec{p("call", "filepath.Base", "filepath.Clean", "url.PathEscape")}, nil),
		rule(langs, "go.ssrf.http", "ssrf", "CWE-918", "high", "medium", "Go 服务端请求伪造", "请求数据流入站 HTTP 客户端。", sources,
			[]PatternSpec{p("call", "http.Get", "http.Post", "http.NewRequest", "client.Get", "client.Do")},
			[]PatternSpec{p("call", "url.QueryEscape", "url.ParseRequestURI")}, nil),
		rule(langs, "go.template.parse", "template", "CWE-1336", "high", "medium", "Go 模板注入", "请求数据作为模板源码解析。", sources,
			[]PatternSpec{p("call", "template.New", "Parse", "ParseFiles")},
			[]PatternSpec{p("call", "template.HTMLEscapeString")}, nil),
		rule(langs, "go.deserialization.gob", "deserialization", "CWE-502", "medium", "medium", "Go 反序列化", "请求数据流入 gob 解码接口。", sources,
			[]PatternSpec{p("call", "Decode", "gob.NewDecoder")}, nil, nil),
		rule(langs, "go.redirect.http", "redirect", "CWE-601", "medium", "medium", "Go 开放重定向", "请求数据流入重定向目标参数（http.Redirect 第 3 参数、gin/echo 第 2 参数）。", sources,
			[]PatternSpec{pArg("call", 3, "http.Redirect", "Redirect"), pArg("call", 2, "c.Redirect", "ctx.Redirect", "ec.Redirect")}, nil, nil),
	}
}
