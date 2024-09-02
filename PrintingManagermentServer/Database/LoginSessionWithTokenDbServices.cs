using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace PrintingManagermentServer.Database
{
    public class LoginSessionWithTokenDbServices : DbTableBase<LoginSessionWithToken>, ILoginSessionWithTokenDbServices
    {
        private readonly DbSet<LoginSessionWithToken> _loginSessionWithToken;

        public LoginSessionWithTokenDbServices(PrintingManagermentDbContext dbContext) : base(dbContext)
        {
            _loginSessionWithToken = this._DbModels;
        }

        public LoginSessionWithToken GetLoginSessionByAccessToken(string accessToken)
        {
            var obj = _loginSessionWithToken.Include(l => l.IncomingToklen)
                .Include(l => l.UserToken).ThenInclude(u => u.Permissions).ThenInclude(p => p.Role)
                .Include(l => l.TokenResponse)
                .Include(l => l.LoginSession)
                .FirstOrDefault(x => x.TokenResponse.AccessToken.Equals(accessToken));

            return obj;
        }
    }

    public interface ILoginSessionWithTokenDbServices: IDbContextBase<LoginSessionWithToken>
    {
        LoginSessionWithToken GetLoginSessionByAccessToken(string accessToken);
    }
}
