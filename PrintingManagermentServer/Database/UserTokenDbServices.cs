using Microsoft.EntityFrameworkCore;
using PrMModels;

namespace PrintingManagermentServer.Database
{
    public class UserTokenDbServices : DbTableBase<UserToken>, IUserTokenDbServices
    {
        private DbSet<UserToken> _userTokenDbServices;

        public UserTokenDbServices(PrintingManagermentDbContext dbContext) : base(dbContext)
        {
            _userTokenDbServices = this._DbModels;
        }

        public UserToken FindByUsername(string userName)
        {
            var obj = _userTokenDbServices.FirstOrDefault(u => u.UserName.Equals(userName));
            return obj;
        }
    }

    public interface IUserTokenDbServices : IDbContextBase<UserToken>
    {
        UserToken FindByUsername(string userName);
    }
}
