using Microsoft.AspNetCore.Authorization;
[Authorize]
public class HomeController : ControllerBase {
  [HttpGet("/home")]
  public string Index() { return "ok"; }
}
