using IssuerOfClaims.Database.Model;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMUserDbServices : DbTableBase<PrMUser>, IPrMUserDbServices
    {
        private DbSet<PrMUser> _PrMUsers { get; set; }

        //private readonly IPrMIdentityUserRoleDbServices _permissionDbServices;
        private readonly IPrMRoleDbServices _roleDbServices;

        public PrMUserDbServices(IPrMAuthenticationContext dbContext, IPrMRoleDbServices roleDbServices) : base(dbContext)
        {
            _PrMUsers = this._DbModels;
            //_permissionDbServices = permissionDbServices;
            _roleDbServices = roleDbServices;

            //var _PrMUsersInclude = _PrMUsers.Include(user => user.PrMPermissions)
            //    .ThenInclude(permission => permission.Role).ToArray();
        }

        /// <summary>
        /// TODO: if functions's names are without "withRelation", then by default, it does not contain object of relation
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public PrMUser GetUserByUserName(string userName)
        {
            var user = _PrMUsers.FirstOrDefault(user => user.UserName.Equals(userName));
            //user.PrMPermissions = GetUserPermission(user.Id);

            return user;
        }

        //public bool CreateNewUser(PrMUser user)
        //{
        //    try
        //    {
        //        _PrMUsers.Add(user);
        //        this.SaveChanges();
        //    }
        //    catch (Exception ex)
        //    {
        //        return false;
        //    }

        //    return true;
        //}

        //private List<PrMIdentityUserRole> GetUserPermission(int userId)
        //{
        //    var permissions = _permissionDbServices.GetByUser(userId);

        //    return permissions;
        //}

        /// <summary>
        /// TODO: when user is created, userName must have, inherit from IdentityUser can be ambigous
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public PrMUser GetUserWithRelation(string userName)
        {
            var user = _PrMUsers
                .Include(u => u.PrMIdentityUserRoles).ThenInclude(p => p.Role)
                .Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.TokenResponse)
                .Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.LoginSession)
                .Include(u => u.ConfirmEmail)
                .FirstOrDefault(user => user.UserName.Equals(userName));

            return user;
        }

        public PrMUser GetUserIncludeConfirmEmail(int id)
        {
            var user = _PrMUsers.Include(user => user.ConfirmEmail)
                .FirstOrDefault(user => user.Id.Equals(id));

            return user;
        }

        public PrMUser InitiateUserWithRoles(string userName, string[] roles, string email = "")
        {
            var user = new PrMUser()
            {
                UserName = userName,
                //PasswordHash = password,
                PasswordHashSalt = "",
                Email = email
            };
            user.PrMIdentityUserRoles = roles.Select(roleName => new PrMIdentityUserRole()
            {
                Role = _roleDbServices.GetRoleByName(roleName),
                User = user
            }).ToList();

            return user;
        }

        public List<PrMUser> GetAllUsersIncludeRelation()
        {
            var users = _PrMUsers
                .Include(u => u.PrMIdentityUserRoles).ThenInclude(p => p.Role)
                .Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.TokenResponse)
                .Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.LoginSession)
                .Include(u => u.ConfirmEmail).ToList();

            return users;
        }

        public PrMUser GetUserWithRelation(int id)
        {
            var user = _PrMUsers
                .Include(user => user.PrMIdentityUserRoles).ThenInclude(p => p.Role)
                .Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.TokenResponse)
                .Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.LoginSession)
                .Include(u => u.ConfirmEmail)
                .First(user => user.Id.Equals(id));

            return user;
        }

        public PrMUser GetUserWithTokenResponse(string userName)
        {
            var user = _PrMUsers
                .Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.LoginSession)
                .Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.TokenResponse)
                .Include(u => u.ConfirmEmail)
                .First(user => user.UserName.Equals(userName));

            return user;
        }
    }

    public interface IPrMUserDbServices : IDbContextBase<PrMUser>
    {
        //bool CreateNewUser(PrMUser user);
        PrMUser GetUserByUserName(string userName);
        PrMUser GetUserIncludeConfirmEmail(int id);
        PrMUser GetUserWithRelation(string userName);
        PrMUser GetUserWithTokenResponse(string userName);
        PrMUser GetUserWithRelation(int id);
        PrMUser InitiateUserWithRoles(string userName, string[] roles, string email = "");
        List<PrMUser> GetAllUsersIncludeRelation();
    }
}
