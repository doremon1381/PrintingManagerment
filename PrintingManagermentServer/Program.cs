using Microsoft.AspNetCore.Authentication.Cookies;
using PrintingManagermentServer.Controllers.Ultility;
using PrMServerUltilities;
using PrMServerUltilities.Identity;

namespace PrintingManagermentServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie((options) =>
                {
                    options.Cookie.Name = "demo";
                    options.ExpireTimeSpan = TimeSpan.FromHours(8);
                    // TODO: will change login redirect path later
                    //options.LoginPath = "/handle1/login";
                    //options.ReturnUrlParameter = "http://127.0.0.1:59867/";
                    options.Events.OnRedirectToLogin = context =>
                    {
                        var identityServerInfo = builder.Configuration.GetSection(IdentityServerConfiguration.IDENTITYSERVER);

                        var identityServerUri = identityServerInfo[IdentityServerConfiguration.AUTHORIZATION_ENDPOINT];
                        var clientId = identityServerInfo[IdentityServerConfiguration.CLIENT_ID];
                        var redirectUri = identityServerInfo[string.Format("{0}:0", IdentityServerConfiguration.REDIRECT_URIS)];

                        var responseRedirectUri = string.Format("{0}?client_id={1}" +
                            "&redirect_uri={2}", identityServerUri, clientId, redirectUri);
                        // TODO: will try to implement nonce
                        //+ "&nonce={}");

                        string nonce = RNGCryptoServicesUltilities.RandomDataBase64url(10);

                        context.Response.StatusCode = 401;
                        context.Response.Headers.Add("ServerLocation", responseRedirectUri);
                        //context.Response.Cookies.Append("nonce", nonce);

                        // TODO: uncommment for wpf app test
                        context.Response.Redirect($"http://127.0.0.1:59867?nonce={nonce}");
                        // TODO: uncommment for wpf app test

                        //context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(
                        //    new
                        //    {
                        //        Location = responseRedirectUri
                        //    }));

                        return Task.CompletedTask;
                    };
                });
            builder.Services.AddSingleton<IConfigurationManager>(builder.Configuration);
            // TODO: will add later
            //builder.Services.AddIdentity<PrMUser, IdentityRole>();
            //.AddEntityFrameworkStores<ApplicationDbContext>();
            builder.Services.AddMvc(mvcOptions =>
            {
                mvcOptions.Conventions.Add(new ControllerNameAttributeConvention());
            });

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
            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();
        }
    }
}
