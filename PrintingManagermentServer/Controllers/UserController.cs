using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using PrintingManagermentServer.Controllers.Ultility;
using PrintingManagermentServer.Database;
using PrMDbModels;
using PrMServerUltilities.Extensions;
using Microsoft.EntityFrameworkCore;

namespace PrintingManagermentServer.Controllers
{
    //[Authorize]
    [ApiController]
    [ControllerName("users")]
    [Route("[controller]")]
    [AllowAnonymous]
    public class UserController : ControllerBase
    {
        //private readonly IUserTokenDbServices _userDbServices;
        private readonly UserManager<UserToken> _userManager;
        //private readonly MailSettings _mailSettings;
        //private readonly IEmailDbServices _emailDbServices;

        public UserController(IUserTokenDbServices userDbServices, UserManager<UserToken> userManager)
        {
            //_userDbServices = userDbServices;
            _userManager = userManager;
            //_mailSettings = mailSettings;
            //_emailDbServices = emailDbServices;
        }

        [HttpGet("all")]
        [Authorize(Policy = "Admin")]
        public async Task<ActionResult> GetAllUser()
        {
            try
            {
                var users = _userManager.Users
                    .Include(u => u.Permissions).ThenInclude(p => p.Role)
                    .Include(u => u.Team)
                    .Include(u => u.TeamManager).Include(tm => tm.Team)
                    .ToList();

                var returnObj = new List<object>();
                users.ForEach(u =>
                {
                    string permissions = "";
                    u.Permissions.ForEach(p =>
                    {
                        permissions += $"{p.Role.RoleName},";
                    });

                    var temp = new
                    {
                        Username = u.UserName,
                        Name = u.FullName,
                        Email = u.Email,
                        Phone = u.PhoneNumber,
                        Roles = permissions,
                        Group = u.Team == null ? "" : u.Team.Name
                    };

                    returnObj.Add(temp);
                });

                var json = JsonConvert.SerializeObject(returnObj);

                return Ok(json);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }
    }
}
