using IssuerOfClaims.Database.Model;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMUserDbServices : DbTableBase<PrMUser>, IPrMUserDbServices
    {
        private DbSet<PrMUser> _PrMUsers { get; set; }

        private readonly IPrMPermissionDbServices _permissionDbServices;

        public PrMUserDbServices(IPrMAuthenticationContext dbContext, IPrMPermissionDbServices permissionDbServices) : base(dbContext)
        {
            _PrMUsers = this._DbModels;
            _permissionDbServices = permissionDbServices;

            var _PrMUsersInclude = _PrMUsers.Include(user => user.PrMPermissions)
                .ThenInclude(permission => permission.Role).ToArray();
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

        public bool CreateNewUser(PrMUser user)
        {
            try
            {
                _PrMUsers.Add(user);
                this.SaveChanges();
            }
            catch (Exception ex)
            {
                return false;
            }

            return true;
        }

        private List<PrMPermission> GetUserPermission(int userId)
        {
            var permissions = _permissionDbServices.GetByUser(userId);

            return permissions;
        }

        /// <summary>
        /// TODO: when user is created, userName must have, inherit from IdentityUser can be ambigous
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public PrMUser GetByUserNameWithRelation(string userName)
        {
            var user = _PrMUsers.Include(user => user.PrMPermissions).ThenInclude(p => p.Role)
                .First(user => user.UserName.Equals(userName));

            return user;
        }

        public PrMUser GetUserIncludeConfirmEmail(int id)
        {
            var user = _PrMUsers.Include(user => user.ConfirmEmail)
                .FirstOrDefault(user => user.Id.Equals(id));

            return user;
        }
    }

    public interface IPrMUserDbServices: IDbContextBase<PrMUser>
    {
        bool CreateNewUser(PrMUser user);
        PrMUser GetUserByUserName(string userName);
        PrMUser GetUserIncludeConfirmEmail(int id);
        PrMUser GetByUserNameWithRelation(string userName);
        
    }
}
