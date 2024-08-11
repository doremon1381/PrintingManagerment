using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMUserStore : UserStore<PrMUser, PrMRole, PrMAuthenticationContext, int, PrMUserClaim, PrMPermission, PrMUserLogin, PrMUserToken, PrMRoleClaim>
    {
        public PrMUserStore(PrMAuthenticationContext context, IdentityErrorDescriber? describer = null) : base(context, describer)
        {
        }
    }
}
