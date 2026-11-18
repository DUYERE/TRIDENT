const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const id = req.query.id;
  const sql = 'SELECT * FROM users WHERE id = ' + id;
  db.query(sql);
  res.send('ok');
});

app.post('/exec', (req, res) => {
  const cmd = req.body.cmd;
  exec('ping ' + cmd);
});

app.get('/safe', (req, res) => {
  // 负例：显式数值转换 + 参数化查询
  const id = parseInt(req.query.id, 10);
  db.query('SELECT * FROM users WHERE id = ?', [id]);
});

app.get('/xss', (req, res) => {
  res.send('<h1>' + req.query.title + '</h1>');
});

app.post('/legacy', (req, res) => {
  // 正例：动态代码执行
  eval(req.body.code);
});

// db.query(req.query.id);
// exec(req.body.cmd);
const NOTE = "eval(req.body.code)";

// 正例（v2）：模板字面量插值进入 SQL
const uname = req.query.uname;
db.query(`SELECT * FROM users WHERE name = '${uname}'`);

// 负例（v2）：模板字面量内无插值的诱饵文本
const decoy = `use db.query(req.query.x) carefully`;
