using IssuerOfClaims.Controllers.Ultility;
using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;

namespace IssuerOfClaims
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            // Add services to the container.

            builder.Services.AddControllers();
            builder.Services.AddDbContext<IPrMAuthenticationContext, PrMAuthenticationContext>(optionsAction =>
            {
                optionsAction.UseSqlServer(builder.Configuration.GetConnectionString(DbUltilities.DatabaseName));
            });
            builder.Services.AddScoped<IPrMUserDbServices, PrMUserDbServices>();
            builder.Services.AddScoped<IPrMClientDbServices, PrMClientDbServices>();
            builder.Services.AddSingleton(AuthorizationResources.GetClients(builder.Configuration));
            //builder.Services.AddScoped<IPrMIdentityServer, PrMIdentityServer>();
            // add asp.net identity
            // will need because in identity server, need to hold login session to 
            //builder.Services.AddIdentity<IdentityUser, IdentityRole>()
            //    .AddUserManager<IdentityUser>();
            //builder.Services.AddPrMIdentityServer()
            //    .Add;
            //builder.Services.AddIdentityServer()
            //    // TODO: for demo and test
            //    .AddInMemoryClients(AuthorizationResources.GetClients(builder.Configuration))
            //    .AddInMemoryIdentityResources(new IdentityResource[] {
            //        new IdentityResources.OpenId(),
            //        new IdentityResources.Profile(),
            //        new IdentityResources.Email(),
            //        new IdentityResources.Phone(),
            //    });
            //.AddAspNetIdentity<CustomClient>();
            builder.Services.AddAuthentication(defaultScheme: "cookies")
                .AddCookie(authenticationScheme: "cookie", configureOptions: (options) =>
                {
                    options.Cookie.Name = "demo";
                    options.ExpireTimeSpan = TimeSpan.FromHours(8);
                    options.LoginPath = "/login";
                });
                //.AddOpenIdConnect();
            builder.Services.AddLogging(options =>
            {
                //options.AddFilter("Duende", LogLevel.Debug);
            });
            // TODO: comment for now
            //builder.Services.AddApiVersioning(apiVersionOptions =>
            //{
            //    apiVersionOptions.DefaultApiVersion = new ApiVersion(1, 0);
            //    apiVersionOptions.AssumeDefaultVersionWhenUnspecified = true;
            //    apiVersionOptions.ReportApiVersions = true;
            //});
            builder.Services.AddMvc(mvcOptions =>
            {
                mvcOptions.Conventions.Add(new ControllerNameAttributeConvention());
            });

            var app = builder.Build();

            SetupPipline(app);
            // I intentionally separate app.run with setupPipline
            // , it's not official protocol as far as I know
            app.Run();
        }

        static void SetupPipline(WebApplication app)
        {
            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();

            //app.UseIdentityServer();
            // duende IdentityServer is already have UseAuthentication,
            // so do not need to have both with app.UseAuthentication
            app.UseAuthentication();

            //app.UseStaticFiles();
            app.UseRouting();

            app.UseAuthorization();

            app.MapControllers();
        }
    }
}
