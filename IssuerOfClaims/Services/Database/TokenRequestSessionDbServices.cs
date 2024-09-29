using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class TokenRequestSessionDbServices : DbTableBase<TokenRequestSession>, ITokenRequestSessionDbServices
    {
        private DbSet<TokenRequestSession> _loginSession;

        public TokenRequestSessionDbServices(IDbContextManager dbContext) : base(dbContext)
        {
            _loginSession = _DbModels;
        }

        public TokenRequestSession FindByAccessToken(string accessToken)
        {
            throw new NotImplementedException();
        }

        public TokenRequestSession CreateTokenRequestSession()
        {
            TokenRequestSession obj = new TokenRequestSession();
            this.Create(obj);

            return obj;
        }
    }

    public interface ITokenRequestSessionDbServices : IDbContextBase<TokenRequestSession>
    {
        TokenRequestSession FindByAccessToken(string accessToken);
        TokenRequestSession CreateTokenRequestSession();
    }
}
