using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using PrintingManagermentServer.Controllers.Ultility;

namespace PrintingManagermentServer.Controllers
{
    [ApiController]
    [ControllerName("handle1")]
    [Route("[controller]")]
    //[EnableCors("MyPolicy")]
    //[Authorize]
    public class Handler1Controller : ControllerBase
    {
        public Handler1Controller() { }

        [HttpGet("login")]
        public ActionResult Index()
        {
            return StatusCode(200);
        }

        [HttpGet("something")]
        [Authorize]
        public ActionResult GetSomething()
        {
            return Ok("'Something' has been called!");
        }
    }
}
