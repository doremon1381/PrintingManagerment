using IssuerOfClaims.Services.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using PrMDbModels;
using PrMServerUltilities.Extensions;
using PrMServerUltilities.Identity;
using System.Security.Claims;
using System.Text.Encodings.Web;
using static PrMServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Services
{
    /// <summary>
    /// TODO: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/write?view=aspnetcore-8.0&viewFallbackFrom=aspnetcore-2.2#per-request-dependencies
    /// </summary>
    public class AuthenticationServices : AuthenticationHandler<JwtBearerOptions>
    {
        private ITokenRequestServices _tokenRequestServices;
        private IClientDbServices _clientDbServices;
        private UserManager<PrMUser> _userManager;
        //private readonly RequestDelegate _next;

        public AuthenticationServices(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder,
            ITokenRequestServices tokenRequestServices, IClientDbServices clientDbServices, UserManager<PrMUser> userManager)
            : base(options, logger, encoder)
        {
            _tokenRequestServices = tokenRequestServices;
            _clientDbServices = clientDbServices;
            _userManager = userManager;
        }

        //// TODO: 
        //public async Task InitializeAsync(AuthenticationScheme scheme, HttpContext context,
        //    ITokenRequestServices tokenRequestServices, IClientDbServices clientDbServices, UserManager<PrMUser> userManager)
        //{
        //    _tokenRequestServices = tokenRequestServices;
        //    _clientDbServices = clientDbServices;
        //    _userManager = userManager;

        //    //await _next(context);
        //}

        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var endpoint = this.Context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() is object)
            {
                return AuthenticateResult.NoResult();
            }

            // TODO: user login
            var headers = this.Request.Headers;
            if (!string.IsNullOrEmpty(this.Context.Request.QueryString.Value))
            {
                var requestQuery = this.Context.Request.QueryString.Value.Remove(0, 1).Split("&");

                var registerHeader = headers["Register"].ToString();
                if (!string.IsNullOrEmpty(registerHeader))
                {
                    // TODO: check if it is register new user request first, because "authorize" enpoint is decorated with [Authorize] attribute.
                    //     : get prompt to use from https://openid.net/specs/openid-connect-prompt-create-1_0.html
                    string prompt = GetValidParameterFromQuery(requestQuery, AuthorizeRequest.Prompt);
                    if (prompt.Equals("create"))
                    {
                        AuthenticationTicket ticket = IssuingTicketForParticularProcess(this.Scheme.Name, registeredProcess: true);

                        return AuthenticateResult.Success(ticket);
                    }
                }

                // TODO: change in flow
                //// TODO: 12.1.  Refresh Request https://openid.net/specs/openid-connect-core-1_0.html
                //string grantType = GetValidParameterFromQuery(requestQuery, TokenRequest.GrantType);
                //if (grantType.Contains(TokenTypes.RefreshToken))
                //{
                //    AuthenticationTicket ticket = IssuingTicketForParticularProcess(this.Scheme.Name, offlineAccessProcess: true);

                //    return AuthenticateResult.Success(ticket);
                //}
            }

            if (string.IsNullOrEmpty(headers.Authorization.ToString()))
                return AuthenticateResult.Fail("Authentication's identity inside request headers is missing!");

            // TODO: authentication allow "Basic" access - username + password
            if (headers.Authorization.ToString().StartsWith(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC))
            {
                var authenticateToken = this.Context.Request.Headers.Authorization.ToString();

                var userNamePassword = authenticateToken.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, "").Trim().ToBase64Decode();
                if (string.IsNullOrEmpty(userNamePassword))
                    return AuthenticateResult.Fail("username and password is empty!");

                string userName = userNamePassword.Split(":")[0];
                string password = userNamePassword.Split(":")[1];

                // TODO: Do authentication of userId and password against your credentials store here
                var user = _userManager.Users
                    .Include(user => user.PrMIdentityUserRoles).ThenInclude(p => p.Role)
                    //.Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.TokenResponse)
                    //.Include(u => u.LoginSessionsWithResponse).ThenInclude(l => l.TokenRequestSession)
                    //.Include(u => u.ConfirmEmails)
                    .FirstOrDefault(u => u.UserName == userName);

                if (user == null)
                    return AuthenticateResult.Fail("User is not found!");

                try
                {
                    if (string.IsNullOrEmpty(user.PasswordHash))
                        return AuthenticateResult.Fail("try another login method, because this user's password is not set!");

                    // TODO: with implicit grant, passwordHash must have when create new user, so let it be
                    //var isPasswordMatched = PasswordUltilities.VerifyHashedPassword(user.PasswordHash, password);

                    var valid = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, password);

                    if (valid == PasswordVerificationResult.Failed)
                        return AuthenticateResult.Fail("wrong password!");

                    #region authenticate reason
                    var principal = GetClaimPrincipal(user);

                    Thread.CurrentPrincipal = principal;
                    if (this.Context != null)
                    {
                        Context.User = principal;
                    }
                    #endregion

                    var ticket = new AuthenticationTicket(principal, this.Scheme.Name);

                    return AuthenticateResult.Success(ticket);
                }
                catch (Exception ex)
                {
                    return AuthenticateResult.Fail(ex.Message);
                }
            }
            // TODO: and "Bearer" token - access token or id token, for now, I'm trying to implement
            //     : https://datatracker.ietf.org/doc/html/rfc9068#JWTATLRequest
            else if (headers.Authorization.ToString().StartsWith(AuthenticationSchemes.AuthorizationHeaderBearer))
            {
                var authenticateToken = this.Context.Request.Headers.Authorization.ToString();

                var bearer = authenticateToken.Replace(AuthenticationSchemes.AuthorizationHeaderBearer, "").Trim();

                var loginSession = _tokenRequestServices.FindByAccessToken(bearer);

                #region authenticate reason
                var principal = GetClaimPrincipal(loginSession.User);

                Thread.CurrentPrincipal = principal;
                if (this.Context != null)
                {
                    Context.User = principal;
                }
                #endregion

                var ticket = new AuthenticationTicket(principal, this.Scheme.Name);

                return AuthenticateResult.Success(ticket);
            }

            // TODO: return none for now
            return AuthenticateResult.Fail("nonce");
        }

        private AuthenticationTicket IssuingTicketForParticularProcess(string schemaName, bool registeredProcess = false, bool offlineAccessProcess = false)
        {
            ClaimsPrincipal claims = new ClaimsPrincipal();

            if (registeredProcess == true && offlineAccessProcess == true)
                throw new InvalidOperationException("Wrong implement!");

            if (registeredProcess)
            {
                claims = GetClaimPrincipalForRegisterUser();
            }
            else if (offlineAccessProcess)
            {
                claims = GetClaimPrincipalForOfflineAccessUser();
            }

            return new AuthenticationTicket(claims, schemaName);
        }

        private string GetValidParameterFromQuery(string[] requestQuery, string parameterType)
        {
            string parameterValue = "";
            requestQuery.GetFromQueryString(parameterType, out parameterValue);

            if (string.IsNullOrEmpty(parameterValue))
                throw new InvalidDataException("Parameter from query string must have value!");

            return parameterValue;
        }

        private ClaimsPrincipal GetClaimPrincipalForRegisterUser()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Anonymous, "RegisterUser")
            };
            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.AUTHENTICATION_SCHEME_ANONYMOUS) });
            return principal;
        }

        private ClaimsPrincipal GetClaimPrincipalForOfflineAccessUser()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Anonymous, "OfflineAccess")
            };
            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.AUTHENTICATION_SCHEME_ANONYMOUS) });
            return principal;
        }

        /// <summary>
        /// TODO: For now, use ClaimTypes of NetCore
        /// use when user login
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private ClaimsPrincipal GetClaimPrincipal(PrMUser user)
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
                new Claim(JwtClaimTypes.EmailVerified, user.IsEmailConfirmed.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };
            user.PrMIdentityUserRoles.ForEach(p =>
            {
                claims.Add(new Claim(ClaimTypes.Role, p.Role.RoleCode));
            });

            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, user.UserName, ClaimTypes.Role) });

            //_UserClaims.Add(user, principal);
            return principal;
        }
    }
}
