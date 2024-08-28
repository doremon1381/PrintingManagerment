using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace PrintingManagermentServer.Services
{
    public class PrMAuthenticationHandler : AuthenticationHandler<JwtBearerOptions>
    {
        public PrMAuthenticationHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
        {
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


                var idToken = headers.Authorization.ToString();
                if (!string.IsNullOrEmpty(idToken))
                {
                    // If the session is valid, return success:
                    var claims = new[] { new Claim(ClaimTypes.Name, "Test") };
                    var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Tokens"));
                    var ticket = new AuthenticationTicket(principal, Scheme.Name);
                    return AuthenticateResult.Success(ticket);

                }
                else
                    // If the token is missing or the session is invalid, return failure:
                    // return AuthenticateResult.Fail("Authentication failed");
                    return AuthenticateResult.Fail("Authentication failed!");
            }
            catch (Exception ex)
            {
                var error = ex.Message;
            }

            return AuthenticateResult.NoResult();
        }
    }
}
