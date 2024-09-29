using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class RoleDbServices : DbTableBase<PrMRole>, IPrMRoleDbServices
    {
        private DbSet<PrMRole> _PrMRoles;

        public RoleDbServices(IDbContextManager dbContext) : base(dbContext)
        {
            _PrMRoles = _DbModels;
        }

        public int Count()
        {
            return _PrMRoles.Count();
        }

        public PrMRole GetRoleByName(string roleName)
        {
            var role = _PrMRoles.First(r => r.RoleName.Equals(roleName));

            return role;
        }
    }

    public interface IPrMRoleDbServices : IDbContextBase<PrMRole>
    {
        int Count();
        PrMRole GetRoleByName(string roleName);
    }
}
