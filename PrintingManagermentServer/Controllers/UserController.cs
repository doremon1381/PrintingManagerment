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
    //[AllowAnonymous]
    public class UserController : ControllerBase
    {
        //private readonly IUserTokenDbServices _userDbServices;
        private readonly UserManager<UserToken> _userManager;
        private readonly IPermissionDbServices _permissionDbServices;
        private readonly IRoleDbServices _roleDbServices;

        //private readonly MailSettings _mailSettings;
        //private readonly IEmailDbServices _emailDbServices;

        public UserController(UserManager<UserToken> userManager, IPermissionDbServices permissionDbServices, IRoleDbServices roleDbServices)
        {
            //_userDbServices = userDbServices;
            _userManager = userManager;
            //_mailSettings = mailSettings;
            //_emailDbServices = emailDbServices;
            _permissionDbServices = permissionDbServices;
            _roleDbServices = roleDbServices;
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

        [Authorize(Policy = "Admin")]
        [HttpPost("update")]
        public async Task<ActionResult> UpdateUSers()
        {
            try
            {
                //Dictionary<string, string> requestBody = new Dictionary<string, string>();
                U[] requestBody;
                using (StreamReader sr = new StreamReader(HttpContext.Request.Body))
                {
                    var temp = await sr.ReadToEndAsync();
                    var srsr = JsonConvert.DeserializeObject<Dictionary<string, U[]>>(temp);
                    requestBody = srsr.Values.FirstOrDefault();
                }

                foreach(var user in requestBody)
                {
                    var currentUser = _userManager.Users.Include(u => u.Permissions).ThenInclude(p => p.Role)
                        .Include(u => u.LoginSessionWithTokens)
                        .Include(u => u.TeamManager)
                        .FirstOrDefault(u => u.UserName.Equals(user.Username));
                    if (currentUser == null)
                        return StatusCode(500, "somehow...");

                    if (user.IsDeleted)
                    {                        
                        await _userManager.DeleteAsync(currentUser);
                    }
                    else if (user.IsModified)
                    {
                        _permissionDbServices.DeleteMany(currentUser.Permissions);
                        currentUser.Permissions = new List<Permission>();
                        List<Permission> newPermissions = new List<Permission>();
                        // TODO: at this step, user from client only change in permission and team
                        var roles = _roleDbServices.GetAll();
                        //var teams = _teamDbServices.FindByName();
                        var permissions = user.Roles.Select(r =>
                        {
                            var t = roles.FirstOrDefault(p => p.RoleName == r);
                            var p = new Permission { 
                                Role = t,
                                User = currentUser
                            };
                            return p;
                        });

                        currentUser.Permissions.AddRange(permissions);
                        await _userManager.UpdateAsync(currentUser);
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }

            return Ok();
        }

        private record U
        (
            string Username,
            string Name,
            string Email,
            string Phone,
            string[] Roles,
            string Group,
            bool IsModified,
            bool IsDeleted,
            bool IsAdmin
        );
    }
}
