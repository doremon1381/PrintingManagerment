using Google.Apis.Auth.OAuth2;
using IssuerOfClaims.Database.Model;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMClientDbServices : DbTableBase<PrMClient>, IPrMClientDbServices
    {
        private DbSet<PrMClient> _PrMClients { get; set; }

        public PrMClientDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            _PrMClients = this._DbModels;
        }

        // TODO: will remove
        public List<PrMClient> GetAllClientWithRelation()
        {
            //var clients = _PrMClients.Include(c => c.AllowedGrantTypes)
            return null;
        }

        public PrMClient GetByIdAndSecret(string id, string clientSecret)
        {
            var client = _PrMClients.FirstOrDefault(c => c.ClientId.Equals(id) && c.ClientSecrets.Contains(clientSecret));

            return client;
        }

        public PrMClient GetById(string id)
        {
            var client = _PrMClients.FirstOrDefault(c => c.ClientId.Equals(id));

            return client;
        }
    }

    public interface IPrMClientDbServices: IDbContextBase<PrMClient>
    {
        //List<PrMClient> GetAllClientWithRelation();
        PrMClient GetByIdAndSecret(string id, string secret);
        PrMClient GetById(string id);
    }
}
