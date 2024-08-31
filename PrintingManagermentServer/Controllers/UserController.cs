using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using PrintingManagermentServer.Controllers.Ultility;
using PrintingManagermentServer.Database;
using PrMServerUltilities.Identity;
using System.Security.Claims;

namespace PrintingManagermentServer.Controllers
{
    [Authorize]
    [ApiController]
    [ControllerName("users")]
    [Route("[controller]")]
    public class UserController: ControllerBase
    {
        private readonly IUserTokenDbServices _userDbServices;

        public UserController(IUserTokenDbServices userDbServices) 
        {
            _userDbServices = userDbServices;
        }

        [HttpGet("all")]
        [Authorize(Policy = "Admin")]
        public async Task<ActionResult> GetAllUser()
        {
            try
            {
                var users = _userDbServices.GetAllWithInclude();

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
