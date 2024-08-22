using IssuerOfClaims.Controllers;
using IssuerOfClaims.Controllers.Ultility;
using IssuerOfClaims.Database;
using IssuerOfClaims.Models;
using IssuerOfClaims.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PrMDbModels;
using PrMServerUltilities.Identity;

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
            builder.Services.AddSingleton<IConfigurationManager>(builder.Configuration);
            // TODO: will change later
            builder.Services.AddScoped<IPrMClientDbServices, PrMClientDbServices>();
            builder.Services.AddScoped<IPrMRoleDbServices, PrMRoleDbServices>();
            //builder.Services.AddScoped<IPrMIdentityUserRoleDbServices, PrMIdentityUserRoleDbServices>();
            builder.Services.AddScoped<IConfirmEmailDbServices, ConfirmEmailDbServices>();
            builder.Services.AddScoped<ITokenResponseDbServices, TokenResponseDbServices>();
            builder.Services.AddScoped<IPrMRequiredLoginSessionDbServices, PrMRequiredLoginSessionDbServices>();
            builder.Services.AddScoped<IPrMUserDbServices, PrMUserDbServices>();
            builder.Services.AddScoped<ILoginSessionWithResponseDbServices, LoginSessionWithResponseDbServices>();
            builder.Services.AddSingleton(builder.Configuration.GetSection("MailSettings").Get<MailSettings>());
            builder.Services.AddSingleton(builder.Configuration.GetSection("Jwt").Get<JwtOptions>());
            // TODO: will add later
            builder.Services.AddIdentityCore<PrMUser>()
                .AddEntityFrameworkStores<PrMAuthenticationContext>()
                .AddDefaultTokenProviders();

            builder.Services.AddScoped<IPrMLoginSessionManager, PrMLoginSessionManager>();

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

            //builder.Services.AddDistributedMemoryCache();
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            //.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
            .AddScheme<JwtBearerOptions, PrMAuthenticationHandler>(JwtBearerDefaults.AuthenticationScheme,
                options =>
                {
                    // TODO: will check later
                    //options.Authority = "PrMIdentityServer";
                    //options.Audience = "http://localhost:3010/";
                    builder.Configuration.Bind("Jwt", options);
                    //options.TokenValidationParameters = new TokenValidationParameters
                    //{
                    //    ValidateIssuer = true,
                    //    //ValidIssuer = "my-firebase-project",
                    //    ValidateAudience = true,
                    //    //ValidAudience = "my-firebase-project",
                    //    ValidateLifetime = true
                    //};
                });
            //builder.Services.AddAuthorization(options => 
            //{
            //    options.AddPolicy("RequireClient", policy => policy.RequireRole("client"));
            //});
            builder.Services.AddMvc(mvcOptions =>
            {
                mvcOptions.Conventions.Add(new ControllerNameAttributeConvention());
            });
            // TODO: comment for now
            //builder.Services.AddCors(options =>
            //{
            //    options.AddPolicy(name: "MyPolicy",
            //        policy =>
            //        {
            //            policy.WithOrigins("http://localhost:3000")
            //                .WithMethods("PUT", "DELETE", "GET", "POST");
            //        });
            //});
            var app = builder.Build();
            // TODO: use for first time run db
            AuthorizationResources.CreateClient(builder.Configuration);
            SetupPipline(app);
            // I intentionally separate app.run with setupPipline
            // , it's not official protocol as far as I know
            app.Run();
        }

        static void SetupPipline(WebApplication app)
        {
            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            // TODO: comment for now
            //app.UseCors();

            app.UseAuthentication();
            app.UseAuthorization();

            // TODO: comment for now
            //app.UseSession();
            app.MapControllers();
        }
    }
}
