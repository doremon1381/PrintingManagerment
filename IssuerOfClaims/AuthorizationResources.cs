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
        internal static IEnumerable<PrMClient> GetClients(IConfigurationManager configuration)
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

            var roles = dbContext.PrMRoles.ToList();

            if (roles.Count == 0)
            {
                roles = new List<PrMRole>()
                {
                    new PrMRole()
                    {
                        RoleName="admin",
                        RoleCode="admin",
                    },
                    new PrMRole()
                    {
                        RoleName="employee",
                        RoleCode="employee",
                    },
                    new PrMRole()
                    {
                        RoleName="designer",
                        RoleCode="designer",
                    },
                    new PrMRole()
                    {
                        RoleName="deliver",
                        RoleCode="deliver",
                    },
                    new PrMRole()
                    {
                        RoleName="manager",
                        RoleCode="manager",
                    },
                    new PrMRole()
                    {
                        RoleName="leader",
                        RoleCode="leader",
                    },
                };

                dbContext.PrMRoles.AddRange(roles);
                dbContext.SaveChanges();
            }

            return clients;
        }

        internal static List<PrMRole> GetRoles(ConfigurationManager configuration)
        {
            var contextOptions = new DbContextOptionsBuilder<PrMAuthenticationContext>()
                 .UseSqlServer(configuration.GetConnectionString(DbUltilities.DatabaseName))
                 .Options;
            var dbContext = new PrMAuthenticationContext(contextOptions, null);

            var roles = dbContext.PrMRoles.ToList();

            if (roles.Count == 0)
            {
                roles = new List<PrMRole>()
                {
                    new PrMRole()
                    {
                        RoleName="admin",
                        RoleCode="admin",
                    },
                    new PrMRole()
                    {
                        RoleName="employee",
                        RoleCode="employee",
                    },
                    new PrMRole()
                    {
                        RoleName="designer",
                        RoleCode="designer",
                    },
                    new PrMRole()
                    {
                        RoleName="deliver",
                        RoleCode="deliver",
                    },
                    new PrMRole()
                    {
                        RoleName="manager",
                        RoleCode="manager",
                    },
                    new PrMRole()
                    {
                        RoleName="leader",
                        RoleCode="leader",
                    },
                };

                dbContext.PrMRoles.AddRange(roles);
                dbContext.SaveChanges();
            }

            return roles;
        }
    }
}
