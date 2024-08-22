using PrintingManagermentServer.Database;
using PrMModels;

namespace PrintingManagermentServer.Services
{
    public class UserTokenDbServices : DbTableBase<UserToken>, IUserTokenDbServices
    {
        public UserTokenDbServices(PrintingManagermentDbContext dbContext) : base(dbContext)
        {
        }
    }

    public interface IUserTokenDbServices: IDbContextBase<UserToken>
    {
    }
}
