#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("PrMClients")]
    [PrimaryKey(nameof(Id))]
#endif
    public class PrMClient : ModelBase
    {
#if DbServer
        [Required]
#endif
        public string ClientId { get; set; }
#if DbServer
        [Required]
#endif
        public List<string> ClientSecrets { get; set; }

        /// <summary>
        /// Specifies the allowed grant types (legal combinations of AuthorizationCode, Implicit, Hybrid, ResourceOwner, ClientCredentials).
        /// </summary>
#if DbServer
        [Required]
#endif
        public List<string> AllowedGrantTypes { get; set; }
        public bool AllowOfflineAccess { get; set; } = false;
        public List<string> RedirectUris { get; set; }
        public List<string> PostLogoutRedirectUris { get; set; }
        public string FrontChannelLogoutUri { get; set; }
        public List<string> AllowedScopes { get; set; }
        public string AuthProviderX509CertUrl { get; set; }

        public PrMClient()
        {
            ClientId = "";
            ClientSecrets = new List<string>();
            AllowedGrantTypes = new List<string>();
            RedirectUris = new List<string>();
            PostLogoutRedirectUris = new List<string>();
            FrontChannelLogoutUri = "";
            AuthProviderX509CertUrl = "";
            AllowedScopes = new List<string>();

        }
    }
}
