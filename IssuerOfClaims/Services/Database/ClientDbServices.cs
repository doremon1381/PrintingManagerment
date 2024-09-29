using Google.Apis.Auth.OAuth2;
using IssuerOfClaims.Database;
using IssuerOfClaims.Database.Model;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class ClientDbServices : DbTableBase<PrMClient>, IClientDbServices
    {
        private DbSet<PrMClient> _PrMClients { get; set; }

        public ClientDbServices(IDbContextManager dbContext) : base(dbContext)
        {
            _PrMClients = _DbModels;
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

    public interface IClientDbServices : IDbContextBase<PrMClient>
    {
        //List<PrMClient> GetAllClientWithRelation();
        PrMClient GetByIdAndSecret(string id, string secret);
        PrMClient GetById(string id);
    }
}
