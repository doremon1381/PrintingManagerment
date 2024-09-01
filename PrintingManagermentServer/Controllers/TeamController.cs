using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PrintingManagermentServer.Controllers.Ultility;

namespace PrintingManagermentServer.Controllers
{
    [Authorize]
    [ApiController]
    [ControllerName("teams")]
    [Route("[controller]")]
    public class TeamController: ControllerBase
    {
        public TeamController() 
        {
            
        }

        [HttpGet("allTeams")]
        public async Task<ActionResult> GetAllOffices()
        {
            return StatusCode(200, "");
        }

        [HttpPost("modify")]
        public async Task<ActionResult> ModifyOffices()
        {
            return StatusCode(200, "");

        }

        [HttpPost("create")]
        public async Task<ActionResult> CreateOffices()
        {
            return StatusCode(200);
        }
    }
}
