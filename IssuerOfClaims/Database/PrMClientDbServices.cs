using IssuerOfClaims.Database.Model;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMClientDbServices: DbTableBase<PrMClient>, IPrMClientDbServices
    {
        private DbSet<PrMClient> _PrMClients { get; set; }

        public PrMClientDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            _PrMClients = this._DbModels;
        }

    }

    public interface IPrMClientDbServices
    {

    }
}
