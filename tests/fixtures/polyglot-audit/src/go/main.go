package main

import (
	"database/sql"
	"net/http"
	"os/exec"
	"strconv"
)

func search(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	q := "SELECT * FROM users WHERE id = " + id
	db.Query(q)
	http.Get("http://" + r.Host)
}

func run(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd)
}

func safe(w http.ResponseWriter, r *http.Request) {
	// 负例：显式数值转换 + 参数化查询
	id, _ := strconv.Atoi(r.FormValue("id"))
	db.Query("SELECT * FROM users WHERE id = ?", id)
}

func templateFromRequest(w http.ResponseWriter, r *http.Request) {
	// 正例：请求数据作为模板源码解析
	text := r.FormValue("tpl")
	template.New("t").Parse(text)
}

func main() {
	http.HandleFunc("/search", search)
	http.HandleFunc("/run", run)
	_ = sql.ErrNoRows
}

// db.Query(r.FormValue("id"))
// exec.Command("sh", "-c", r.FormValue("cmd"))
const note = "db.Query(r.FormValue(\"id\"))"

// 正例（v2）：开放重定向（http.Redirect 第 3 参数）
target := r.FormValue("url")
http.Redirect(w, r, target, 302)
