using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PrintingManagermentServer.Controllers.Ultility;

namespace PrintingManagermentServer.Controllers
{
    [ApiController]
    [ControllerName("handle1")]
    [Route("[controller]")]
    [Authorize]
    public class Handler1Controller: ControllerBase
    {
    }
}
