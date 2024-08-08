using IssuerOfClaims.Database;
using IssuerOfClaims.Database.Model;
using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using PrMDbModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IssuerOfClaims
{
    public static class AuthorizationResources
    {
        /// <summary>
        /// only use at server's initialization
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        public static IEnumerable<PrMClient> GetClients(IConfigurationManager configuration)
        {
            var contextOptions = new DbContextOptionsBuilder<PrMAuthenticationContext>()
                 .UseSqlServer(configuration.GetConnectionString(DbUltilities.DatabaseName))
                 .Options;

            var clientDb = new PrMClientDbServices(new PrMAuthenticationContext(contextOptions, null));
            var clients = clientDb.GetAll();

            if (clients.Count == 0)
            {
                var printingManagermentServer = new PrMClient();
                printingManagermentServer.ClientId = "PrintingManagermentServer";
                printingManagermentServer.ClientSecrets.Add(new PrMSecret("secretServer".Sha256()).Value);
                printingManagermentServer.AllowedGrantTypes.Add(GrantType.ClientCredentials);
                printingManagermentServer.AllowedScopes.Add("oauth2");

                var printingManagermentDbServer = new PrMClient();
                printingManagermentDbServer.ClientId = "PrintingManagermentDbServer";
                printingManagermentDbServer.ClientSecrets.Add(new PrMSecret("secretServerDb".Sha256()).Value);
                printingManagermentDbServer.AllowedGrantTypes.Add(GrantType.ClientCredentials);
                printingManagermentDbServer.AllowedScopes.Add("oauth2");

                var printingManagermentWeb = new PrMClient();
                printingManagermentWeb.ClientId = "PrintingManagermentWeb";
                printingManagermentWeb.ClientSecrets.Add(new PrMSecret("secretWeb".Sha256()).Value);
                printingManagermentWeb.AllowedGrantTypes.Add(GrantType.AuthorizationCode);
                printingManagermentWeb.RedirectUris.Add("http://localhost:5173/signin-oidc");
                printingManagermentWeb.PostLogoutRedirectUris.Add("http://localhost:5173/");
                printingManagermentWeb.FrontChannelLogoutUri = "http://localhost:5173/signout-oidc";
                printingManagermentWeb.AllowedScopes.AddRange(new string[] {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,

                    //"api1", "api2.read_only"
                });

                var newClients = new List<PrMClient>() { printingManagermentServer, printingManagermentDbServer, printingManagermentWeb };

                clientDb.AddMany(newClients);

                clients = newClients;
            }

            return clients;
        }
    }

    /// <summary>
    /// TODO: will delete
    /// </summary>
    public static class RNGCryptoServicesUltilities
    {
        // rfc 7636 impliment
        public static void GetMitigateAttackMethod()
        {
            string status = RandomStringGeneratingWithLength(32);
            string code_verifier = RandomStringGeneratingWithLength(32);
            string code_challenge = Base64UrlEncodeNoPadding(code_verifier.WithSHA265());
            string code_challenge_method = "S256";
        }

        public static string RandomStringGeneratingWithLength(int length)
        {
            RNGCryptoServiceProvider strGenerator = new RNGCryptoServiceProvider();
            byte[] arr = new byte[length];
            strGenerator.GetBytes(arr, 0, length);

            return Base64UrlEncodeNoPadding(arr);
        }

        private static string Base64UrlEncodeNoPadding(byte[] str)
        {
            string base64 = Convert.ToBase64String(str);

            // convert base64 to base64url
            base64.Replace("+", "-");
            base64.Replace("/", "_");

            // strip padding
            base64.Replace("=", "");

            return base64;
        }

        private static byte[] WithSHA265(this string str)
        {
            byte[] newByteArr = Encoding.ASCII.GetBytes(str);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(newByteArr);
        }

        public static string GetStringWithSHA256(this string str)
        {
            byte[] newByteArr = Encoding.ASCII.GetBytes(str);
            SHA256Managed sha256 = new SHA256Managed();
            var hashBytes = sha256.ComputeHash(newByteArr);

            StringBuilder sb = new StringBuilder();

            foreach (var b in hashBytes)
            {
                sb.Append(b.ToString());
            }

            return sb.ToString();
        }
    }
}
