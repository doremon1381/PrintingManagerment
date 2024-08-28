using Microsoft.EntityFrameworkCore;
using PrintingManagermentServer.Models;
using PrMModels;

namespace PrintingManagermentServer.Database
{
    public class RoleDbServices : DbTableBase<Role>, IRoleDbServices
    {
        private DbSet<Role> _Role;

        public RoleDbServices(PrintingManagermentDbContext dbContext) : base(dbContext)
        {
            _Role = this._DbModels;
        }
    }

    public interface IRoleDbServices: IDbContextBase<Role>
    {
        
    }
}
