import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route('/search', methods=['GET'])
def search():
    name = request.args.get('name')
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
    return "ok"


@app.route('/run')
def run():
    host = request.form['host']
    os.system('ping ' + host)
    return "ok"


@app.route('/safe')
def safe():
    name = request.args.get('name')
    # 负例：参数化查询，用户输入位于第二个参数
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    return "ok"


@app.route('/render')
def render():
    title = request.args.get('title')
    # 负例：显式转义
    safe_title = html.escape(title)
    return render_template_string("<h1>" + safe_title + "</h1>")


@app.route('/raw')
def raw():
    return render_template_string("<h1>" + request.args.get('title') + "</h1>")


@app.route('/legacy')
def legacy():
    # 正例：代码执行与不安全反序列化
    eval(request.args.get('code'))
    return pickle.loads(request.data)


# cursor.execute("SELECT " + request.args.get('name'))
# os.system(request.form['host'])
NOTE = "eval(request.args.get('code'))"

# 正例（v2）：f-string 插值进入 SQL
name = request.args.get('name')
cursor.execute(f"SELECT * FROM users WHERE name = {name}")

# 负例（v2）：普通字符串与 r 前缀字符串不插值
sql_plain = "SELECT * FROM users WHERE name = {request.args.get('name')}"
cursor.execute(sql_plain)
sql_raw = rf"SELECT * FROM users WHERE name = {request.args.get('name')}"
cursor.execute(sql_raw)
