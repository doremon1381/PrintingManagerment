using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PrintingManagermentServer.Client;
using PrintingManagermentServer.Controllers;
using PrintingManagermentServer.Controllers.Ultility;
using PrintingManagermentServer.Database;
using PrintingManagermentServer.Services;
using PrMModels;
using PrMServerUltilities;
using PrMServerUltilities.Extensions;
using PrMServerUltilities.Identity;
using System.Net;
using System.Text;
using static PrMServerUltilities.Identity.OidcConstants;

namespace PrintingManagermentServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            builder.Services.AddDbContext<IPrintingManagermentDbContext, PrintingManagermentDbContext>(optionsAction =>
            {
                optionsAction.UseSqlServer(builder.Configuration.GetConnectionString(DbUltilities.DatabaseName));
            });
            builder.Services.AddSingleton<IConfigurationManager>(builder.Configuration);
            builder.Services.AddScoped<ILoginSessionWithTokenDbServices, LoginSessionWithTokenDbServices>();
            builder.Services.AddScoped<ILoginSessionManager, LoginSessionManager>();
            builder.Services.AddScoped<IUserTokenDbServices, UserTokenDbServices>();
            builder.Services.AddSingleton(builder.Configuration.GetSection("IdentityServer").Get<ClientSettings>());

            //builder.Services.AddCors(options =>
            //{
            //    options.AddPolicy(name: "MyPolicy",
            //        policy =>
            //        {
            //            policy.WithOrigins("http://localhost:3010")
            //                .WithMethods("PUT", "DELETE", "GET", "POST");
            //        });
            //});
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddScheme<JwtBearerOptions, CustomAuthenticationHandler>(JwtBearerDefaults.AuthenticationScheme,options => 
                {
                    builder.Configuration.Bind("Jwt", options);
                });
            builder.Services.AddMvc(mvcOptions =>
            {
                mvcOptions.Conventions.Add(new ControllerNameAttributeConvention());
            });
            // TODO: use for first time run db
            AuthorizationResources.CreateRoles(builder.Configuration);
            var app = builder.Build();

            SetupPipline(app);
            app.Run();
        }

        private static void SetupPipline(WebApplication app)
        {
            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();
            #region later
            // TODO: remind me that function can be used
            //app.UseStatusCodePages(async context =>
            //{
            //    if (context.HttpContext.Response.StatusCode == 401)
            //    {
            //        var noContentResponse = new
            //        {
            //            errorCode = "401",
            //            message = "resource inexistent"
            //        };
            //        var responeString = JsonConvert.SerializeObject(noContentResponse);
            //        var requestContent = new StringContent(responeString);
            //        requestContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            //        context.HttpContext.Response.Body = await requestContent.ReadAsStreamAsync();
            //        context.HttpContext.Response.StatusCode = 401;
            //    }
            //});
            #endregion
            app.UseStaticFiles();
            app.UseRouting();
            //app.UseCors();

            app.UseAuthentication();
            app.UseMiddleware<PrMUnauthorizedResponseMiddleware>();
            app.UseAuthorization();


            app.MapControllers();
        }
    }
}
