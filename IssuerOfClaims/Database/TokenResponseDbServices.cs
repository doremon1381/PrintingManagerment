using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class TokenResponseDbServices : DbTableBase<TokenResponse>, ITokenResponseDbServices
    {
        private DbSet<TokenResponse> _TokenResponses;
        public TokenResponseDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            _TokenResponses = this._DbModels;
        }

        //public TokenResponse GetResponseByUserId(int userId)
        //{
        //    var obj = _TokenResponses.FirstOrDefault(t => t.)
        //}
    }

    public interface ITokenResponseDbServices: IDbContextBase<TokenResponse>
    {
        //TokenResponse GetResponseByUserId(int userId);
    }
}
