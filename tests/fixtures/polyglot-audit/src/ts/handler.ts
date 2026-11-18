export function render(req: any, res: any): void {
  const name: string = req.query.name;
  res.send('<h1>' + name + '</h1>');
}

export function safe(req: any, res: any): void {
  // 负例：显式 HTML 转义
  const name: string = escapeHtml(req.query.name);
  res.send(name);
}

// 正例（v2）：模板字面量插值进入响应
res.send(`user search: ${req.query.name}`);
