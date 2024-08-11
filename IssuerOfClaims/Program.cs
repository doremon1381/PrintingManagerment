using IssuerOfClaims.Controllers.Ultility;
using IssuerOfClaims.Database;
using IssuerOfClaims.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

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
            builder.Services.AddScoped<IPrMRoleDbServices, PrMRoleDbServices>();
            builder.Services.AddScoped<IPrMPermissionDbServices, PrMPermissionDbServices>();
            builder.Services.AddScoped<IConfirmEmailDbServices, ConfirmEmailDbServices>();
            builder.Services.AddSingleton(AuthorizationResources.GetClients(builder.Configuration));
            //builder.Services.Configure<MailSettings>(builder.Configuration.GetSection("MailSettings"));
            MailSettings mailSettings = builder.Configuration.GetSection("MailSettings").Get<MailSettings>();
            JwtOptions jwtOptions = builder.Configuration.GetSection("Jwt").Get<JwtOptions>();
            builder.Services.AddSingleton(mailSettings);
            builder.Services.AddSingleton(jwtOptions);
            builder.Services.AddSingleton<IConfigurationManager>(builder.Configuration);
            // TODO: will add later
            builder.Services.AddIdentity<PrMUser, PrMRole>(options =>
            {
                options.User.RequireUniqueEmail = false;
            })
            .AddEntityFrameworkStores<PrMAuthenticationContext>()
            .AddUserStore<PrMUserStore>()
            .AddDefaultTokenProviders();
            //.AddSignInManager<PrMUser>()
            ////.AddUserManager<PrMUser>()
            //.AddRoleManager<IdentityRole>().AddClaimsPrincipalFactory<PrMUser>();

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
            builder.Services.AddDistributedMemoryCache();

            builder.Services.AddSession(options =>
            {
                options.Cookie.Name = "PrMSession";
                options.IdleTimeout = TimeSpan.FromSeconds(10);
                //options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
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

            app.UseAuthentication();
            //app.UseStaticFiles();
            app.UseRouting();

            app.UseAuthorization();

            app.UseSession();

            app.MapControllers();
        }
    }
}
