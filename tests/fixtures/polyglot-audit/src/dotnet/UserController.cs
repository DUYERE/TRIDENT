using System;
using Microsoft.AspNetCore.Mvc;

namespace Demo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        [HttpGet("search")]
        public IActionResult Search()
        {
            string id = Request.QueryString["id"];
            string sql = "SELECT * FROM users WHERE id = " + id;
            var cmd = new SqlCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
            return Ok();
        }

        [HttpPost("ping")]
        public IActionResult Ping()
        {
            string host = Request.Form["host"];
            Process.Start("ping " + host);
            return Ok();
        }

        // 负例：参数化查询（safe call 在 sink 附近出现）
        [HttpGet("safe")]
        public IActionResult Safe()
        {
            string id = Request.QueryString["id"];
            var cmd = new SqlCommand();
            cmd.CommandText = "SELECT * FROM users WHERE id = @id";
            cmd.Parameters.AddWithValue("@id", id);
            return Ok();
        }

        // 正例：不安全反序列化
        [HttpPost("legacy")]
        public IActionResult Legacy()
        {
            var formatter = new BinaryFormatter();
            object payload = formatter.Deserialize(Request.Body);
            return Ok();
        }
    }
}

// string sql = "SELECT * FROM " + Request.QueryString["id"];
// Process.Start(Request.Form["host"]);
const string Note = "cmd.CommandText = Request.Form[\"id\"]";

// 正例（v2）：插值字符串拼接请求参数进入 SQL 命令
var sort = Request.Query["sort"];
var query = $"SELECT * FROM users ORDER BY {sort}";
var cmd2 = new SqlCommand(query, conn);
