using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMPermissionDbServices : DbTableBase<PrMPermission>, IPrMPermissionDbServices
    {
        private DbSet<PrMPermission> _PrMPermissions;
        //private IPrMRoleDbServices _roleDbServices;

        public PrMPermissionDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            _PrMPermissions = this._DbModels;
            //_roleDbServices = roleDbServices;
        }

        public List<PrMPermission> GetByUser(int userId)
        {
            var pm = _PrMPermissions.Where(p => p.UserId.Equals(userId)).ToList();

            return pm;
        }
    }

    public interface IPrMPermissionDbServices: IDbContextBase<PrMPermission>
    {
        List<PrMPermission> GetByUser(int userId);

    }
}
