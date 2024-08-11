using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMRoleDbServices : DbTableBase<PrMRole>, IPrMRoleDbServices
    {
        private DbSet<PrMRole> _PrMRoles;

        public PrMRoleDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            _PrMRoles = this._DbModels;
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

    public interface IPrMRoleDbServices: IDbContextBase<PrMRole>
    {
        int Count();
        PrMRole GetRoleByName(string roleName);
    }
}
