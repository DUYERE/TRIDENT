package codescan

import "testing"

func TestFileScopeClassification(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"app/controller/Index.php", "project"},
		{"public/index.php", "project"},
		{"vendor/laravel/framework/src/Illuminate/Foundation/Application.php", "vendor"},
		{"node_modules/lodash/lodash.js", "vendor"},
		{"extend/PHPExcel/Documentation/Examples/Calculations/DateTime/DATEVALUE.php", "vendor"},
		{"public/static/public/jquery/jquery.min.js", "vendor"},
		{"public/static/public/layui/lay/modules/code.js", "vendor"},
		{"public/static/app.min.js", "generated"},
		{"dist/app.bundle.js", "generated"},
	}
	for _, tc := range cases {
		if got := fileScope(tc.path); got != tc.want {
			t.Errorf("fileScope(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
