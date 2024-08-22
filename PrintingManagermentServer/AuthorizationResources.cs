using PrMServerUltilities.Extensions;
using Microsoft.EntityFrameworkCore;
using PrMServerUltilities.Identity;
using PrintingManagermentServer.Database;
using PrintingManagermentServer.Models;

namespace PrintingManagermentServer
{
    public static class AuthorizationResources
    {
        /// <summary>
        /// only use at server's initialization
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        internal static bool CreateRoles(IConfigurationManager configuration)
        {
            var contextOptions = new DbContextOptionsBuilder<PrintingManagermentDbContext>()
                 .UseSqlServer(configuration.GetConnectionString(DbUltilities.DatabaseName))
                 .Options;

            var dbContext = new PrintingManagermentDbContext(contextOptions, null);
            var roles = dbContext.Roles.ToList();

            if (roles.Count == 0)
            {
                roles = new List<Role>()
                {
                    new Role()
                    {
                        RoleName="admin",
                        RoleCode="admin",
                    },
                    new Role()
                    {
                        RoleName="employee",
                        RoleCode="employee",
                    },
                    new Role()
                    {
                        RoleName="designer",
                        RoleCode="designer",
                    },
                    new Role()
                    {
                        RoleName="deliver",
                        RoleCode="deliver",
                    },
                    new Role()
                    {
                        RoleName="manager",
                        RoleCode="manager",
                    },
                    new Role()
                    {
                        RoleName="leader",
                        RoleCode="leader",
                    },
                };

                dbContext.Roles.AddRange(roles);
                dbContext.SaveChanges();
            }

            return true;
        }
    }
}
