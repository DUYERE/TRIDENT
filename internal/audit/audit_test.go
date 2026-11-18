package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/project"
)

func fixtureSnapshot(t *testing.T) *project.Snapshot {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "java-maven"))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "source")
	copyTree(t, source, copied)
	return importSnapshot(t, copied)
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected fixture entry %s", relative)
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func importSnapshot(t *testing.T, source string) *project.Snapshot {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "snapshot")
	imported, err := project.Import(context.Background(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := project.Open(context.Background(), destination, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot
}

func snapshotFromFiles(t *testing.T, files map[string]string) *project.Snapshot {
	t.Helper()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		target := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return importSnapshot(t, source)
}

func endpoint(report Report, path string) Endpoint {
	for _, endpoint := range report.Endpoints {
		if endpoint.Path == path {
			return endpoint
		}
	}
	return Endpoint{}
}

func TestInspectFixtureSpringEndpoints(t *testing.T) {
	snapshot := fixtureSnapshot(t)
	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	javaFiles := 0
	for _, entry := range snapshot.Manifest().Entries {
		if strings.HasSuffix(entry.Path, ".java") {
			javaFiles++
		}
	}
	if report.Partial || report.Coverage.JavaFilesScanned != javaFiles || report.Coverage.ControllersFound != 1 || report.Coverage.EndpointsFound != 3 {
		t.Fatalf("coverage: %+v partial=%v", report.Coverage, report.Partial)
	}
	controller := report.Controllers[0]
	if controller.Class != "CustomerController" || controller.Symbol != "example.synthetic.CustomerController" || controller.BasePathStatus != "resolved" || len(controller.BasePaths) != 1 || controller.BasePaths[0] != "/synthetic/customers" {
		t.Fatalf("controller: %+v", controller)
	}
	unsafe := endpoint(report, "/synthetic/customers/unsafe")
	if unsafe.HTTPMethods[0] != "GET" || unsafe.Method != "unsafe" || unsafe.Symbol != "example.synthetic.CustomerController.unsafe" || unsafe.Annotation != "GetMapping" || unsafe.Anchor != "fixture:unsafe-http-source" || unsafe.PathStatus != "resolved" {
		t.Fatalf("unsafe endpoint: %+v", unsafe)
	}
	if len(unsafe.Parameters) != 1 || unsafe.Parameters[0].Name != "name" || unsafe.Parameters[0].Type != "String" || unsafe.Parameters[0].BindingName != "name" || len(unsafe.Parameters[0].Bindings) != 1 || unsafe.Parameters[0].Bindings[0] != "RequestParam" {
		t.Fatalf("unsafe parameters: %+v", unsafe.Parameters)
	}
	if endpoint(report, "/synthetic/customers/parameterized").Anchor != "fixture:safe-http-source" {
		t.Fatal("parameterized anchor missing")
	}
	if endpoint(report, "/synthetic/customers/dynamic").Anchor != "fixture:dynamic-http-source" {
		t.Fatal("dynamic anchor missing")
	}
	for _, endpoint := range report.Endpoints {
		if endpoint.Class == "CustomerRepository" || endpoint.Class == "DynamicCustomerLookup" {
			t.Fatalf("non-controller produced endpoint: %+v", endpoint)
		}
	}
	if report.Coverage.JavaAST != "not_available" || report.Coverage.TaintAnalysis != "not_run" || report.Coverage.RuntimeStatus != "not_run" {
		t.Fatalf("coverage overclaimed: %+v", report.Coverage)
	}
}

func TestInspectBindingsPathArraysAndUnresolvedExpressions(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/C.java": `package demo;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping({"/v1", "/v2"})
public class C {
    private String text = "@GetMapping(\"/from-string\")";
    // @GetMapping("/from-comment")
    @GetMapping(value = {"/a", "/b"})
    public String multi(@RequestParam(name = "q", required = false) String q) { return q; }
    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public void both(@PathVariable("id") long id, @RequestBody Payload payload) {}
    @GetMapping(PATH_CONST)
    public void dynamic() {}
    public void helper() {}
}
`,
		"src/main/java/demo/D.java": `package demo;
public class D {
    @GetMapping("/not-a-controller")
    public void nope() {}
}
`,
	})
	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial {
		t.Fatal("unresolved path should be partial")
	}
	if len(report.Controllers) != 1 || report.Controllers[0].BasePathStatus != "resolved" || len(report.Controllers[0].BasePaths) != 2 {
		t.Fatalf("controllers: %+v", report.Controllers)
	}
	if endpoint(report, "/from-string").Path != "" || endpoint(report, "/from-comment").Path != "" {
		t.Fatal("comment or string matched as an annotation")
	}
	var multi, both, dynamic int
	for _, endpoint := range report.Endpoints {
		switch endpoint.Method {
		case "multi":
			multi++
			if endpoint.PathStatus != "resolved" || endpoint.Parameters[0].Required != "false" || endpoint.Parameters[0].BindingName != "q" {
				t.Fatalf("multi endpoint: %+v", endpoint)
			}
		case "both":
			both++
			if endpoint.MethodStatus != "specified" || len(endpoint.HTTPMethods) != 2 || len(endpoint.Parameters) != 2 || endpoint.Parameters[0].BindingName != "id" || endpoint.Parameters[1].Type != "Payload" {
				t.Fatalf("both endpoint: %+v", endpoint)
			}
		case "dynamic":
			dynamic++
			if endpoint.PathStatus != "unresolved" || endpoint.PathReason != "non_literal_path" {
				t.Fatalf("dynamic endpoint: %+v", endpoint)
			}
		}
	}
	if multi != 4 || both != 2 || dynamic != 1 || len(report.Endpoints) != 7 {
		t.Fatalf("endpoint product mismatch: multi=%d both=%d dynamic=%d total=%d", multi, both, dynamic, len(report.Endpoints))
	}
	found := false
	for _, limitation := range report.Limitations {
		if strings.HasPrefix(limitation, "controller_marker_missing:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("non-controller mapping not reported: %v", report.Limitations)
	}
}

func TestInspectNeutralisesTextBlocksAndSkipsNestedClasses(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/Blocks.java": `package demo;
@RestController
public class Blocks {
    private String block = """
        @GetMapping("/from-text-block")
        """;
}
`,
		"src/main/java/demo/Outer.java": `package demo;
@RestController
public class Outer {
    @GetMapping("/outer")
    public String outer() { return "ok"; }
    @RestController
    static class Nested {
        @GetMapping("/nested")
        public String nested() { return "nested"; }
    }
}
`,
	})
	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.JavaFilesRejected != 0 || report.Coverage.JavaFilesScanned != 2 {
		t.Fatalf("text block file must stay analysable: %+v", report.Coverage)
	}
	if endpoint(report, "/from-text-block").Path != "" {
		t.Fatal("text block content matched as an annotation")
	}
	if endpoint(report, "/outer").Path == "" || endpoint(report, "/nested").Path != "" {
		t.Fatalf("nested class handling: %+v", report.Endpoints)
	}
	if report.Coverage.NestedClassesSkipped != 1 {
		t.Fatalf("nested class not counted: %+v", report.Coverage)
	}
}

func TestInspectUnquoteJava(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/E.java": `package demo;
@RestController
public class E {
    @GetMapping("/a\u002Fb")
    public void escaped() {}
    @GetMapping("/line\nbreak")
    public void rejected() {}
}
`,
	})
	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint(report, "/a/b").Method != "escaped" {
		t.Fatalf("unicode escape not decoded: %+v", report.Endpoints)
	}
	for _, endpoint := range report.Endpoints {
		if endpoint.Method == "rejected" && (endpoint.PathStatus != "unresolved" || endpoint.PathReason != "non_literal_path") {
			t.Fatalf("invalid escaped path was not unresolved: %+v", endpoint)
		}
	}
	if len(report.Endpoints) != 2 || !report.Partial {
		t.Fatalf("invalid escaped path coverage: %+v partial=%v", report.Endpoints, report.Partial)
	}
}

func TestInspectJAXRSAndServletEntries(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/example/JaxrsResource.java": `package example;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
@Path("/api/users")
public class JaxrsResource {
  @GET
  @Path("/{id}")
  @Produces(MediaType.TEXT_HTML)
  public String get(@PathParam("id") String id, @QueryParam("q") String q) { return q; }
  @POST
  public String create(@QueryParam("name") String name) { return name; }
}`,
		"src/main/java/example/HelloServlet.java": `package example;
import javax.servlet.http.*;
import javax.servlet.annotation.WebServlet;
@WebServlet(urlPatterns = {"/hello", "/hi"})
public class HelloServlet extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) { resp.getWriter().write("x"); }
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) { }
  public void helper() { }
}`,
	})
	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Endpoint{}
	for _, item := range report.Endpoints {
		byPath[item.Path+" "+strings.Join(item.HTTPMethods, ",")] = item
	}
	get, ok := byPath["/api/users/{id} GET"]
	if !ok {
		t.Fatalf("jax-rs GET missing: %+v", report.Endpoints)
	}
	if !get.ResponseBody || len(get.Produces) != 1 || get.Produces[0] != "text/html" || len(get.Parameters) != 2 || get.Parameters[0].Bindings[0] != "PathParam" {
		t.Fatalf("jax-rs GET shape: %+v", get)
	}
	if _, ok := byPath["/api/users POST"]; !ok {
		t.Fatalf("jax-rs POST missing: %+v", report.Endpoints)
	}
	if _, ok := byPath["/hello GET"]; !ok {
		t.Fatalf("servlet GET missing: %+v", report.Endpoints)
	}
	if _, ok := byPath["/hi POST"]; !ok {
		t.Fatalf("servlet POST missing: %+v", report.Endpoints)
	}
	if report.Coverage.ControllersFound != 2 || report.Coverage.EndpointsFound != 6 {
		t.Fatalf("coverage: %+v", report.Coverage)
	}
}

func TestInspectProducesAndResponseBody(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/Rest.java": `package demo;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
@RestController
public class Rest {
    @GetMapping(value = "/html", produces = {"text/html", MediaType.APPLICATION_JSON_VALUE})
    public String html(@RequestParam("q") String q) { return q; }
    @GetMapping(value = "/constant", produces = MediaType.TEXT_HTML_VALUE)
    public String constant(@RequestParam("q") String q) { return q; }
    @GetMapping(value = "/dynamic", produces = CustomMediaTypes.HTML)
    public String dynamic(@RequestParam("q") String q) { return q; }
    @GetMapping("/absent")
    public String absent(@RequestParam("q") String q) { return q; }
}
`,
		"src/main/java/demo/View.java": `package demo;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
@Controller
public class View {
    @GetMapping("/view")
    public String view(@RequestParam("q") String q) { return q; }
    @ResponseBody
    @GetMapping("/body")
    public String body(@RequestParam("q") String q) { return q; }
}
`,
	})
	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	html := endpoint(report, "/html")
	if html.ProducesStatus != "resolved" || len(html.Produces) != 2 || html.Produces[0] != "text/html" || html.Produces[1] != "application/json" || !html.ResponseBody {
		t.Fatalf("literal produces: %+v", html)
	}
	constant := endpoint(report, "/constant")
	if constant.ProducesStatus != "resolved" || len(constant.Produces) != 1 || constant.Produces[0] != "text/html" {
		t.Fatalf("MediaType constant produces: %+v", constant)
	}
	dynamic := endpoint(report, "/dynamic")
	if dynamic.ProducesStatus != "unresolved" || len(dynamic.Produces) != 0 {
		t.Fatalf("unresolved produces: %+v", dynamic)
	}
	absent := endpoint(report, "/absent")
	if absent.ProducesStatus != "absent" || !absent.ResponseBody {
		t.Fatalf("absent produces: %+v", absent)
	}
	view := endpoint(report, "/view")
	if view.ResponseBody || view.ProducesStatus != "absent" {
		t.Fatalf("view endpoint: %+v", view)
	}
	body := endpoint(report, "/body")
	if !body.ResponseBody {
		t.Fatalf("ResponseBody endpoint: %+v", body)
	}
}

func TestInspectNoJavaSource(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{"README.md": "synthetic\n"})
	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.JavaFilesScanned != 0 {
		t.Fatalf("unexpected coverage: %+v", report.Coverage)
	}
	found := false
	for _, limitation := range report.Limitations {
		if limitation == "no_java_source_found" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing limitation: %v", report.Limitations)
	}
}
