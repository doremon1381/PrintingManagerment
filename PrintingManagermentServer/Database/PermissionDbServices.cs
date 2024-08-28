using Microsoft.EntityFrameworkCore;
using PrintingManagermentServer.Models;

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
    }

    public interface IPermissionDbServices: IDbContextBase<Permission>
    {
        bool AddRole(Role role);
    }
}
