using IssuerOfClaims.Database;
using IssuerOfClaims.Database.Model;
using PrMServerUltilities.Extensions;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;
using PrMServerUltilities.Identity;

namespace IssuerOfClaims
{
    public static class AuthorizationResources
    {
        /// <summary>
        /// only use at server's initialization
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        internal static bool CreateClient(IConfigurationManager configuration)
        {
            var contextOptions = new DbContextOptionsBuilder<PrMAuthenticationContext>()
                 .UseSqlServer(configuration.GetConnectionString(DbUltilities.DatabaseName))
                 .Options;

            var dbContext = new PrMAuthenticationContext(contextOptions, null);

            var clientDb = new PrMClientDbServices(dbContext);
            var clients = clientDb.GetAll();

            if (clients.Count == 0)
            {
                var printingManagermentServer = new PrMClient();
                printingManagermentServer.ClientId = "PrintingManagermentServer";
                printingManagermentServer.ClientSecrets = (new PrMSecret("secretServer".Sha256()).Value);
                printingManagermentServer.AllowedGrantTypes = (GrantType.ClientCredentials);
                printingManagermentServer.RedirectUris = ("http://localhost:5173/signin-oidc");
                printingManagermentServer.PostLogoutRedirectUris = ("http://localhost:5173/");
                printingManagermentServer.FrontChannelLogoutUri = "http://localhost:5173/signout-oidc";
                printingManagermentServer.AllowedScopes = $"{IdentityServerConstants.StandardScopes.OpenId},{IdentityServerConstants.StandardScopes.Profile},{IdentityServerConstants.StandardScopes.Email},{Constants.CustomScope.Role}";
                //"api1", "api2.read_only"

                var printingManagermentDbServer = new PrMClient();
                printingManagermentDbServer.ClientId = "PrintingManagermentDbServer";
                printingManagermentDbServer.ClientSecrets = (new PrMSecret("secretServerDb".Sha256()).Value);
                printingManagermentDbServer.AllowedGrantTypes = (GrantType.ClientCredentials);
                printingManagermentDbServer.AllowedScopes = ("oauth2");

                var printingManagermentWeb = new PrMClient();
                printingManagermentWeb.ClientId = "PrintingManagermentWeb";
                printingManagermentWeb.ClientSecrets = (new PrMSecret("secretWeb".Sha256()).Value);
                printingManagermentWeb.AllowedGrantTypes = (GrantType.AuthorizationCode);
                printingManagermentWeb.RedirectUris = ("http://localhost:5173/signin-oidc");
                printingManagermentWeb.PostLogoutRedirectUris = ("http://localhost:5173/");
                printingManagermentWeb.FrontChannelLogoutUri = "http://localhost:5173/signout-oidc";
                printingManagermentWeb.AllowedScopes = $"{IdentityServerConstants.StandardScopes.OpenId},{IdentityServerConstants.StandardScopes.Profile},{IdentityServerConstants.StandardScopes.Email},{Constants.CustomScope.Role}";

                var newClients = new List<PrMClient>() { printingManagermentServer, printingManagermentDbServer, printingManagermentWeb };

                clientDb.AddMany(newClients);

                clients = newClients;
            }

            var roles = dbContext.PrMRoles.ToList();

            return true;
        }
    }
}
