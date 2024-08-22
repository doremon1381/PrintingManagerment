using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMRequiredLoginSessionDbServices : DbTableBase<PrMRequiredLoginSession>, IPrMRequiredLoginSessionDbServices
    {
        private DbSet<PrMRequiredLoginSession> _loginSession;

        public PrMRequiredLoginSessionDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            _loginSession = this._DbModels;
        }

        public PrMRequiredLoginSession FindByAccessToken(string accessToken)
        {
            throw new NotImplementedException();
        }
    }

    public interface IPrMRequiredLoginSessionDbServices : IDbContextBase<PrMRequiredLoginSession>
    {
        PrMRequiredLoginSession FindByAccessToken(string accessToken);
    }
}
