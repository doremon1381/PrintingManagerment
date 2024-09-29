using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class TokenResponseDbServices : DbTableBase<TokenResponse>, ITokenResponseDbServices
    {
        private DbSet<TokenResponse> _TokenResponses;
        public TokenResponseDbServices(IDbContextManager dbContext) : base(dbContext)
        {
            _TokenResponses = _DbModels;
        }

        public TokenResponse CreateTokenResponse()
        {
            var obj = new TokenResponse();
            this.Create(obj);

            return obj;
        }

        public TokenResponse CreateTokenResponse(TokenRequestHandler session)
        {
            var obj = new TokenResponse()
            {
                TokenRequestHandler = session,
            };

            this.Create(obj);

            return obj;
        }
    }

    public interface ITokenResponseDbServices : IDbContextBase<TokenResponse>
    {
        //TokenResponse GetResponseByUserId(int userId);
        TokenResponse CreateTokenResponse();
        TokenResponse CreateTokenResponse(TokenRequestHandler session);
    }
}
