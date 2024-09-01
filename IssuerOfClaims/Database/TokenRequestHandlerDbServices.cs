using Azure.Core;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class TokenRequestHandlerDbServices : DbTableBase<TokenRequestHandler>, ITokenRequestHandlerDbServices
    {
        //private readonly ILoginSessionWithResponseDbServices _loginSessionDbServices;
        private readonly DbSet<TokenRequestHandler> _loginSession;

        public TokenRequestHandlerDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            //_loginSessionDbServices = loginSessionDbServices;
            _loginSession = this._DbModels;
        }

        public TokenRequestHandler FindByAccessToken(string accessToken)
        {
            var obj = _loginSession
                .Include(l => l.User)
                .Include(l => l.TokenResponse)
                .Include(l => l.TokenRequestSession)
                .Include(l => l.TokenExternal)
                .FirstOrDefault(l => l.TokenResponse.AccessToken.Equals(accessToken));

            return obj;
        }

        public TokenRequestHandler FindByRefreshToken(string refreshToken)
        {
            var obj = _loginSession
                .Include(l => l.User)
                .Include(l => l.TokenResponse)
                .Include(l => l.TokenRequestSession)
                .Include(l => l.TokenExternal)
                .FirstOrDefault(l => l.TokenResponse.RefreshToken.Equals(refreshToken));

            return obj;
        }

        public TokenRequestHandler FindLoginSessionWithAuthorizationCode(string authorizationCode)
        {
            var obj = _loginSession
                .Include(l => l.User)
                .Include(l => l.TokenResponse)
                .Include(l => l.TokenRequestSession)
                .Include(l => l.TokenExternal)
                .FirstOrDefault(l => l.TokenRequestSession.AuthorizationCode.Equals(authorizationCode));

            return obj;
        }
    }

    public interface ITokenRequestHandlerDbServices : IDbContextBase<TokenRequestHandler>
    {
        TokenRequestHandler FindByAccessToken(string accessToken);
        TokenRequestHandler FindByRefreshToken(string refreshToken);
        TokenRequestHandler FindLoginSessionWithAuthorizationCode(string authorizationCode);
    }
}
