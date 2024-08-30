using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using PrMModels;
using PrMServerUltilities.Identity;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text.Encodings.Web;
using static PrMServerUltilities.Identity.OidcConstants;

namespace PrintingManagermentServer.Services
{
    public class PrMAuthenticationHandler : AuthenticationHandler<JwtBearerOptions>
    {
        private readonly ILoginSessionManager _loginSessionManager;
        private readonly IConfiguration _configuration;

        public PrMAuthenticationHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, ILoginSessionManager loginSessionManager, IConfiguration configuration) : base(options, logger, encoder)
        {
            _loginSessionManager = loginSessionManager;
            _configuration = configuration;
        }

        /// <summary>
        /// TODO: will done this late
        /// </summary>
        /// <returns></returns>
        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // Read the token from request headers/cookies
            // Check that it's a valid session, depending on your implementation
            try
            {
                var context = Context;
                var headers = context.Request.Headers;

                var endpoint = Context.GetEndpoint();
                if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() is object)
                {
                    return AuthenticateResult.NoResult();
                }

                if (Context.Request.Method.Equals("OPTIONS"))
                {
                    return AuthenticateResult.NoResult();
                }


                var accesstoken = headers.Authorization.ToString();
                if (!string.IsNullOrEmpty(accesstoken))
                {
                    //// If the session is valid, return success:
                    //var claims = new[] { new Claim(ClaimTypes.Name, "Test") };
                    //var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Tokens"));
                    //var ticket = new AuthenticationTicket(principal, Scheme.Name);
                    //return AuthenticateResult.Success(ticket);
                    accesstoken = accesstoken.Replace("Bearer", "").Trim();

                    var loginSession = _loginSessionManager.GetLoginSessionByAccessToken(accesstoken);
                    if (!TokenExtensions.VerifySignature(accesstoken, _configuration.GetSection("Jwt_access_token:Key").Value))
                        return AuthenticateResult.Fail("token is wrong");

                    if (loginSession.UserToken == null)
                        return AuthenticateResult.Fail("Internal server error!");

                    #region authenticate reason
                    var principal = GetClaimPrincipal(loginSession.UserToken);

                    Thread.CurrentPrincipal = principal;
                    if (this.Context != null)
                    {
                        Context.User = principal;
                    }
                    #endregion
                    var ticket = new AuthenticationTicket(principal, this.Scheme.Name);

                    return AuthenticateResult.Success(ticket);
                }
                else
                    // If the token is missing or the session is invalid, return failure:
                    // return AuthenticateResult.Fail("Authentication failed");
                    return AuthenticateResult.Fail("Does not have access token!");
            }
            catch (Exception ex)
            {
                var error = ex.Message;
                return AuthenticateResult.Fail(ex.Message);
            }

            //return AuthenticateResult.Fail("internal server error!");
        }


        /// <summary>
        /// TODO: For now, use ClaimTypes of NetCore
        /// use when user login
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private ClaimsPrincipal GetClaimPrincipal(UserToken user)
        {
            var claims = new List<Claim>
            {
                new Claim("Username", user.UserName),
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Password),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.MobilePhone, user.PhoneNumber),
                new Claim(ClaimTypes.Gender, user.Gender),
                new Claim(JwtClaimTypes.Picture, user.Avatar),
                new Claim(JwtClaimTypes.UpdatedAt, user.UpdateTime.ToString()),
                new Claim(JwtClaimTypes.EmailVerified, user.EmailConfirmed.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };
            user.Permissions.ForEach(p =>
            {
                claims.Add(new Claim(ClaimTypes.Role, p.Role.RoleCode));
            });

            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.AUTHENTICATION_SCHEME_BEARER, user.UserName, ClaimTypes.Role) });

            //_UserClaims.Add(user, principal);
            return principal;
        }
    }
}
