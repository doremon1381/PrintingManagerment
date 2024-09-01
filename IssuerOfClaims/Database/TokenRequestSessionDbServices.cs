using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class TokenRequestSessionDbServices : DbTableBase<TokenRequestSession>, ITokenRequestSessionDbServices
    {
        private DbSet<TokenRequestSession> _loginSession;

        public TokenRequestSessionDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            _loginSession = this._DbModels;
        }

        public TokenRequestSession FindByAccessToken(string accessToken)
        {
            throw new NotImplementedException();
        }
    }

    public interface ITokenRequestSessionDbServices : IDbContextBase<TokenRequestSession>
    {
        TokenRequestSession FindByAccessToken(string accessToken);
    }
}
