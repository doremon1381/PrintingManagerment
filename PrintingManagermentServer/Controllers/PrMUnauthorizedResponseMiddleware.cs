using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Primitives;
using PrintingManagermentServer.Models;
using PrintingManagermentServer.Services;
using PrMServerUltilities;
using PrMServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;

namespace PrintingManagermentServer.Controllers
{
    /// <summary>
    /// from https://dotnettutorials.net/lesson/401-http-status-codein-asp-net-core-web-api/#:~:text=The%20HTTP%20401%20Status%20Code,to%20get%20the%20requested%20response.
    /// </summary>
    public class PrMUnauthorizedResponseMiddleware
    {
        // Field to store the next middleware in the pipeline
        private readonly RequestDelegate _next;
        private readonly IConfigurationManager _configuration;

        // Constructor to initialize the middleware with the next RequestDelegate
        public PrMUnauthorizedResponseMiddleware(RequestDelegate next, IConfigurationManager configuration)
        {
            _next = next; // Assign the next middleware to the private field
            _configuration = configuration;
        }

        // Method that gets called for each request to handle authentication
        public async Task InvokeAsync(HttpContext context)
        {
            string method = context.Request.Method;
            string endpointUrl = context.Request.Host.ToString();

            AddHeadersToAllowCORS(context);

            // TODO: for now, I assume that every request using this particular method and endpoint, is used for preflight in CORS, I will learn about it later
            if (method.Equals("OPTIONS") && endpointUrl.Equals("localhost:7209"))
            {
                context.Response.StatusCode = 200;
                return;// Short-circuit the pipeline, preventing further middleware execution
            }

            // TODO: for allowing anonymous endpoint can be reached
            var endpoint = context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() is object)
            {
                await _next(context);
                return;
            }

            // Custom authorization logic here
            // Call the method to check authorization
            if (HasAuthorizationToken(context, out string authorization))
            {
                // TODO: get access token in jwt form from user-agent

                var handler = new JwtSecurityTokenHandler();
                var jwtSecurityToken = handler.ReadJwtToken(authorization);

            }
            else
            {
                var identityServerInfo = _configuration.GetSection(IdentityServerConfiguration.IDENTITYSERVER);

                context.Response.StatusCode = StatusCodes.Status302Found; // Set the response status code to 302
                context.Response.ContentType = "application/json"; // Set the response content type to JSON

                var identityServerUri = identityServerInfo[IdentityServerConfiguration.AUTHORIZATION_ENDPOINT];
                var clientId = identityServerInfo["client_id"];
                var redirectUri = identityServerInfo["redirect_uris:0"];

                if (identityServerInfo == null
                    || string.IsNullOrEmpty(identityServerUri)
                    || string.IsNullOrEmpty(redirectUri))
                {
                    context.Response.StatusCode = 500;
                    return;
                }

                //string responseType = "code";
                // TODO: remove responseMode for now
                //string responseMode = "";
                var nonce = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(32);
                string code_verifier = RNGCryptoServicesUltilities.RandomDataBase64url(32);
                string code_challenge = RNGCryptoServicesUltilities.Base64urlencodeNoPadding(code_verifier.WithSHA265());
                string code_challenge_method = "S256";
                string clientState = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(32);

                context.Request.Query.TryGetValue("state", out StringValues state);
                // TODO: by default, implicit grant with form_post will not be call, comment for now
                //var responseRedirectUri = string.Format("{0}?client_id={1}&redirect_uri={2}&response_type={3}&response_mode={4}&redirect_uri={5}&scope=openid%20profile%20email&nonce={6}", 
                //    identityServerUri, clientId, System.Uri.EscapeDataString(redirectUri));
                var responseRedirectUri = string.Format("{0}?client_id={1}&redirect_uri={2}&nonce={3}&code_challenge={4}&code_challenge_method={5}&client_state={6}",
                    identityServerUri, clientId, System.Uri.EscapeDataString(redirectUri), nonce, code_challenge, code_challenge_method, clientState);

                // TODO: 
                var loginSessionDraft = new LoginSessionWithToken()
                {
                    LoginSession = new LoginSession()
                    {
                        CodeChallenge = code_challenge,
                        CodeVerifier = code_verifier,
                        CodeChallengeMethod = code_challenge_method,
                        Nonce = nonce,
                        ClientState = clientState
                    }
                };
                LoginSessionManager.AddDraft(loginSessionDraft);

                // Create a custom response object
                var responseBody = new
                {
                    status = 302,
                    state = state,
                    message = "redirect uri is inside response header!"
                };

                //context.Response.StatusCode = 302;
                context.Response.Headers.Append("state", state);

                // TODO: I don't know why if add "Location" as key in response header, the response will be sent in vuejs's web is with status code 200,
                //     : but if I modify the name, for example, to "Location1", then the response will has status code 302 as I set to it before...
                context.Response.Headers.Append("IdentityLocation", responseRedirectUri);
                // Serialize the custom response object to JSON and write it to the response body
                await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(responseBody));
                //await context.Response.StartAsync();
                return;// Short-circuit the pipeline, preventing further middleware execution
            }

            // If the user is authorized, pass the request to the next middleware in the pipeline
            await _next(context);
        }

        private void AddHeadersToAllowCORS(HttpContext context)
        {
            context.Response.Headers.Append("Access-Control-Allow-Origin", "*");
            context.Response.Headers.Append("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS");
            context.Response.Headers.Append("Access-Control-Allow-Headers", "Origin, Content-Type, X-Auth-Token, Authorization, state");
            context.Response.Headers.Append("Access-Control-Allow-Credentials", "true");
        }


        //// To generate token
        //private string GenerateToken(UserToken user, string nonce)
        //{
        //    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        //    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        //    var claims = new List<Claim>();

        //    if (string.IsNullOrEmpty(nonce))
        //    {
        //        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.UserName));
        //    }
        //    else
        //    {
        //        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.UserName));
        //        claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
        //    }

        //    user.Roles.ForEach(r =>
        //    {
        //        claims.Add(new Claim(ClaimTypes.Role, r));
        //    });

        //    var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
        //        _configuration["Jwt:Audience"],
        //        claims,
        //        expires: DateTime.Now.AddMinutes(15),
        //        signingCredentials: credentials);


        //    return new JwtSecurityTokenHandler().WriteToken(token);

        //}

        // Private method to check authorization
        private bool HasAuthorizationToken(HttpContext context, out string authorization)
        {
            authorization = context.Request.Headers.Authorization.ToString();
            var isAuthorized = false;
            if (!string.IsNullOrEmpty(authorization))
                isAuthorized = true;

            // Simulate unauthorized for this example
            return isAuthorized; // Always return false to simulate an unauthorized request
        }
    }
}
