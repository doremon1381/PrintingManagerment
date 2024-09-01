using IssuerOfClaims.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using PrMDbModels;
using PrMServerUltilities.Extensions;
using PrMServerUltilities.Identity;
using System.Security.Claims;
using System.Text.Encodings.Web;
using static PrMServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Services
{
    public class PrMAuthenticationHandler : AuthenticationHandler<JwtBearerOptions>
    {
        //private IPrMUserManager _authenticateServices;
        private IPrMLoginSessionManager _loginSessionManager;
        private IPrMUserDbServices _userDbServices;
        private IPrMClientDbServices _clientDbServices;
        private UserManager<PrMUser> _userManager;

        public PrMAuthenticationHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder
            , IPrMLoginSessionManager loginSessionManager, IPrMUserDbServices userDbServices, IPrMClientDbServices clientDbServices, UserManager<PrMUser> userManager) 
            : base(options, logger, encoder)
            //, IPrMUserManager authenticateServices
        {
            //_authenticateServices = authenticateServices;
            _loginSessionManager = loginSessionManager;
            _userDbServices = userDbServices;
            _clientDbServices = clientDbServices;
            _userManager = userManager;
        }

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
                var requestQuerry = this.Context.Request.QueryString.Value.Remove(0, 1).Split("&");

                var registerHeader = headers["Register"].ToString();
                if (!string.IsNullOrEmpty(registerHeader))
                {
                    // TODO: check if it is register new user request first, because "authorize" enpoint is decorated with [Authorize] attribute.
                    //     : get prompt to use from https://openid.net/specs/openid-connect-prompt-create-1_0.html
                    requestQuerry.GetFromQueryString(AuthorizeRequest.Prompt, out string prompt);
                    if (!string.IsNullOrEmpty(prompt)
                        && prompt.Equals("create"))
                    {
                        var registerClaim = GetClaimPrincipalForRegisterUser();
                        var ticket = new AuthenticationTicket(registerClaim, this.Scheme.Name);
                        return AuthenticateResult.Success(ticket);
                    }
                }

                // TODO: 12.1.  Refresh Request https://openid.net/specs/openid-connect-core-1_0.html
                requestQuerry.GetFromQueryString(TokenRequest.GrantType, out string grantType);
                if (!string.IsNullOrEmpty(grantType)
                    && grantType.Contains(TokenTypes.RefreshToken))
                {
                    var registerClaim = GetClaimPrincipalForOfflineAccessUser();
                    var ticket = new AuthenticationTicket(registerClaim, this.Scheme.Name);
                    return AuthenticateResult.Success(ticket);
                }

                //// TODO: because inside this step is login, so logicaly client is not need for this, only user-credentitals is need
                //requestQuerry.GetFromQueryString(AuthorizeRequest.ClientId, out string clientId);
                //var client = _clientDbServices.GetById(clientId);
                //if (client == null)
                //    return AuthenticateResult.Fail("No client for clientId 's in header!");
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
                var user = _userDbServices.GetUserWithRelation(userName);

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

                var loginSession = _loginSessionManager.FindByAccessToken(bearer);

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
