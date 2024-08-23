using PrintingManagermentServer.Models;

namespace PrintingManagermentServer.Database
{
    public class LoginSessionWithTokenDbServices : DbTableBase<LoginSessionWithToken>, ILoginSessionWithTokenDbServices
    {
        public LoginSessionWithTokenDbServices(PrintingManagermentDbContext dbContext) : base(dbContext)
        {
        }
    }

    public interface ILoginSessionWithTokenDbServices: IDbContextBase<LoginSessionWithToken>
    {
    }
}
