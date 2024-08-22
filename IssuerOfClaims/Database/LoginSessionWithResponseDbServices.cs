using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class LoginSessionWithResponseDbServices : DbTableBase<LoginSessionWithResponse>, ILoginSessionWithResponseDbServices
    {
        //private readonly ILoginSessionWithResponseDbServices _loginSessionDbServices;
        private readonly DbSet<LoginSessionWithResponse> _loginSession;

        public LoginSessionWithResponseDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            //_loginSessionDbServices = loginSessionDbServices;
            _loginSession = this._DbModels;
        }

        public LoginSessionWithResponse FindByAccessToken(string accessToken)
        {
            var obj = _loginSession
                .Include(l => l.User)
                .Include(l => l.TokenResponse)
                .Include(l => l.LoginSession)
                .Include(l => l.TokenExternal)
                .FirstOrDefault(l => l.TokenResponse.AccessToken.Equals(accessToken));

            return obj;
        }

        public LoginSessionWithResponse FindLoginSessionWithAuthorizationCode(string authorizationCode)
        {
            var obj = _loginSession
                .Include(l => l.User)
                .Include(l => l.TokenResponse)
                .Include(l => l.LoginSession)
                .Include(l => l.TokenExternal)
                .FirstOrDefault(l => l.LoginSession.AuthorizationCode.Equals(authorizationCode));

            return obj;
        }
    }

    public interface ILoginSessionWithResponseDbServices : IDbContextBase<LoginSessionWithResponse>
    {
        LoginSessionWithResponse FindByAccessToken(string accessToken);
        LoginSessionWithResponse FindLoginSessionWithAuthorizationCode(string authorizationCode);
    }
}
