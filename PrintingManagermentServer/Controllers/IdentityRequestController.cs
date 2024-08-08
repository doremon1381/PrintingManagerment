using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PrintingManagermentServer.Controllers.Ultility;

namespace PrintingManagermentServer.Controllers
{
    [ApiController]
    [AllowAnonymous]
    [Route("[controller]")]
    //[ApiVersion("1.0")]
    [ControllerName("oauth2")]
    public class IdentityRequestController: ControllerBase
    {
        public IdentityRequestController() { }

        [HttpGet("authentication/google")]
        public async Task<ActionResult> GoogleAuthenticating()
        {
            // send accesstoken to identityserver and get jwt token or id token

            // create claimprincipal, save to httpcontext

            // return jwt token as id token from identity server

            return new StatusCodeResult(200);
        }
    }
}
