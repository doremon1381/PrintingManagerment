using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace PrintingManagermentServer.Database
{
    public class PermissionDbServices : DbTableBase<Permission>, IPermissionDbServices
    {
        private readonly DbSet<Permission> _Permissions;

        public PermissionDbServices(PrintingManagermentDbContext dbContext) : base(dbContext)
        {
            _Permissions = this._DbModels;
        }

        public bool AddRole(Role role)
        {
            //_Permissions.
            throw new NotImplementedException();
        }

        public bool DeletePermissionFromUser(Permission deleted)
        {
            return Delete(deleted);
        }
    }

    public interface IPermissionDbServices: IDbContextBase<Permission>
    {
        bool AddRole(Role role);
        bool DeletePermissionFromUser(Permission deleted);
    }
}
