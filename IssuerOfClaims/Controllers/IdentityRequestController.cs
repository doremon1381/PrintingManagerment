using IssuerOfClaims.Controllers.Ultility;
using IssuerOfClaims.Database;
using PrMServerUltilities.Extensions;
using IssuerOfClaims.Models;
using IssuerOfClaims.Services;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using Newtonsoft.Json;
using PrMDbModels;
using PrMServerUltilities;
using PrMServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Web;
using static PrMServerUltilities.Identity.OidcConstants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using System;
using IssuerOfClaims.Database.Model;

namespace IssuerOfClaims.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //[ApiVersion("1.0")]
    [ControllerName("oauth2")]
    //[EnableCors("MyPolicy")]
    // TODO: https://openid.net/specs/openid-connect-core-1_0.html
    //     : try to implement from this specs
    //     : for now, I dont intend to add https://datatracker.ietf.org/doc/html/rfc8414 (response for a request for "/.well-known/oauth-authorization-server"), I will think about it late
    public class IdentityRequestController : ControllerBase
    {
        private readonly ILogger<IdentityRequestController> _logger;
        private readonly IPrMUserDbServices _userDbServices;

        private readonly UserManager<PrMUser> _userManager;
        private readonly IConfigurationManager _configuration;
        private readonly IConfirmEmailDbServices _emailDbServices;
        private readonly MailSettings _mailSettings;
        private readonly IPrMLoginSessionManager _loginSessionManager;
        private readonly IPrMClientDbServices _clientDbServices;

        public IdentityRequestController(ILogger<IdentityRequestController> logger, IConfigurationManager configuration
            , IPrMUserDbServices userDbServices, UserManager<PrMUser> userManager, IPrMLoginSessionManager loginSessionManager
            , IConfirmEmailDbServices emailDbServices, MailSettings mailSettings, IPrMClientDbServices clientDbServices)
        {
            _logger = logger;
            _configuration = configuration;
            //_httpClientFactory = httpClientFactory;

            _userDbServices = userDbServices;
            _userManager = userManager;
            _emailDbServices = emailDbServices;
            _mailSettings = mailSettings;

            _loginSessionManager = loginSessionManager;
            _clientDbServices = clientDbServices;
        }

        /// <summary>
        /// authorization_endpoint
        /// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// Authentication Request Validation
        /// </summary>
        /// <returns></returns>
        [HttpGet("authorize")]
        [Authorize]
        public async Task<ActionResult> AuthorizationAsync()
        {
            // 1. Get authorization request from server
            // 2. Return an http 302 message to server, give it a nonce cookie (for now, ignore this part),
            //    if asking for google, then send a redirect to google to get authorization code
            //    if basic access (I mean implicit grant - form_post or not), then return a redirect to another request to identity server - send request to "authentication/basicAccess" route
            // 3.
            var requestQuerry = HttpContext.Request.QueryString.Value.Remove(0, 1).Split("&");


            // TODO: from https://openid.net/specs/openid-connect-prompt-create-1_0.html
            //     : When the prompt parameter is used in an authorization request to the authorization endpoint with the value of create,
            //     : it indicates that the user has chosen to be shown the account creation experience rather than the login experience
            requestQuerry.GetFromQueryString(AuthorizeRequest.Prompt, out string prompt);

            // TODO: try to add nonce in flow, will check it late
            //     : because "state" still RECOMMENDED in some case, so I will use it when it's provided for identity server
            requestQuerry.GetFromQueryString(AuthorizeRequest.State, out string state);

            // TODO: try to add nonce in flow, will check it late
            //     : because "nonce" still OPTIONAL in some case, so I will use it when it's provided for identity server
            requestQuerry.GetFromQueryString(AuthorizeRequest.Nonce, out string nonce);

            //TODO: base on scope, I will add claims in id token, so it will need to be verified with client's scope in memory or database
            //    : Verify that a scope parameter is present and contains the openid scope value.
            //    : (If no openid scope value is present, the request may still be a valid OAuth 2.0 request but is not an OpenID Connect request.)
            requestQuerry.GetFromQueryString(AuthorizeRequest.Scope, out string scope);
            scope = System.Uri.UnescapeDataString(scope);

            // TODO: need to compare with existing client in memory or database
            requestQuerry.GetFromQueryString(AuthorizeRequest.ClientId, out string clientId);
            if (string.IsNullOrEmpty(clientId))
                return StatusCode(400, "client id is mismatch!");

            var client = _clientDbServices.GetById(clientId);
            if (client == null)
                return StatusCode(400, "client id is wrong!");
            string[] redirectUris = client.RedirectUris.Split(",");
            // TODO: because in implicit grant flow, redirectUri is use to redirect to user-agent, 
            //     : in logically, client does not know it before user-agent send a redirect_uri to client
            //     : with browser's work, I think many browser can be user-agent, so it will be safe when client asks for redirect_uri from user-agent
            requestQuerry.GetFromQueryString(AuthorizeRequest.RedirectUri, out string redirectUri);
            redirectUri = System.Uri.UnescapeDataString(redirectUri);
            if (string.IsNullOrEmpty(redirectUri))
                return StatusCode(400, "Redirect uri is need for send a response back to where it needs!");
            if (!redirectUris.Contains(redirectUri))
                return StatusCode(400, "redirectUri is mismatch!");

            if (string.IsNullOrEmpty(scope))
                return StatusCode(ProtectedResourceErrors.InsufficientScope.StatusCodeWithError(), ProtectedResourceErrors.InsufficientScope);

            //if (string.IsNullOrEmpty(state))
            //    return StatusCode(400, "State of request must be implemented to avoid cross-site request forgery!");
            // https://openid.net/specs/openid-connect-prompt-create-1_0.html
            // TODO: validate propmt need to wait
            if (!string.IsNullOrEmpty(prompt)
                && prompt.Equals("create"))
            {
                return await RegisterUserAsync(requestQuerry, state, scope, nonce, redirectUri, clientId);
            }

            //var webServerConfiguration = _configuration.GetSection(IdentityServerConfiguration.WEB_SERVER);

            // TODO: why code is not included in request's header,
            //     : because I like it to be include in query's string!
            if (!HttpContext.Request.QueryString.HasValue)
                return StatusCode(400, "Request must containt query string for authorization!");

            requestQuerry.GetFromQueryString(AuthorizeRequest.ResponseType, out string responseType);

            // check response type
            if (string.IsNullOrEmpty(responseType))
                return StatusCode(400, "Response type can not be null or empty!");
            if (!Constants.SupportedResponseTypes.Contains(responseType))
                return StatusCode(400, "response type is not support. String input maybe wrong!");

            // check response mode
            requestQuerry.GetFromQueryString(AuthorizeRequest.ResponseMode, out string responseMode);

            // TODO: by default when response mode is not set for response type is , use 
            if (string.IsNullOrEmpty(responseMode))
                responseMode = GetDefaultResponseModeByResponseType(responseType);

            var headers = HttpContext.Request.Headers;


            if (scope.Contains(IdentityServerConstants.StandardScopes.OpenId))
                switch (responseType)
                {
                    case ResponseTypes.Code:
                        return await AuthorizationCodeFlowAsync(requestQuerry, responseMode, redirectUri, state, scope, nonce, clientId, headers);
                    //break;
                    case ResponseTypes.IdToken:
                        return await ImplicitGrantWithFormPostAsync(requestQuerry, responseMode, redirectUri, state, scope, nonce, clientId, headers);
                    //break;
                    // TODO: will implement another flow if I have time
                    default:
                        break;
                }
            else
            {
                // TODO: if in scope doesnot have openid, it still valid in some case but it's not an Authentication Request that use Oauth2 as standard
            }


            return StatusCode(500, "Not yet know why...");
        }

        #region authorization code flow
        /// <summary>
        /// TODO: Authorization Server Authenticates End-User: https://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="requestQuerry"></param>
        /// <param name="responseMode"></param>
        /// <param name="redirectUri"></param>
        /// <param name="state"></param>
        /// <param name="scope"></param>
        /// <param name="nonce"></param>
        /// <param name="headers"></param>
        /// <returns></returns>
        private async Task<ActionResult> AuthorizationCodeFlowAsync(string[] requestQuerry, string responseMode, string redirectUri, string state, string scope, string nonce, string clientId, IHeaderDictionary headers)
        {
            // TODO: comment for now
            //     : by using AuthenticateHanlder, in this step, authenticated is done
            //     : get user, create authorization code, save it to login session and out

            // By using [Authorize], in this step, user in httpcontext must be set before this
            var userClaims = HttpContext.User;

            // TODO: create authorization code
            var authorizationCode = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(32);
            // TODO: by using authorization before this part, so it should has an user in HttpContext
            var user = await _userManager.GetUserAsync(userClaims);

            var client = _clientDbServices.GetById(clientId);
            if (client == null)
                return StatusCode(400, "clientid may wrong!");
            if (!VerifyScope(scope, client))
                return StatusCode(400, "scope is not allowed!");

            // TODO: add authorization code to loginSession
            // TODO: set loginSession info
            var sessionAndResponse = _loginSessionManager.CreateUserLoginSession(user, client);

            requestQuerry.GetFromQueryString(AuthorizeRequest.CodeChallenge, out string codeChallenge);
            requestQuerry.GetFromQueryString(AuthorizeRequest.CodeChallengeMethod, out string codeChallengeMethod);
            //requestQuerry.GetFromQueryString("client_state", out string clientState);

            sessionAndResponse.TokenRequestSession.CodeChallengeMethod = codeChallengeMethod;
            sessionAndResponse.TokenRequestSession.CodeChallenge = codeChallenge;
            sessionAndResponse.TokenRequestSession.AuthorizationCode = authorizationCode;
            sessionAndResponse.TokenRequestSession.Nonce = nonce;
            //sessionAndResponse.LoginSession.ClientState = clientState;
            sessionAndResponse.TokenRequestSession.Scope = scope;
            sessionAndResponse.TokenRequestSession.IsOfflineAccess = scope.Contains(StandardScopes.OfflineAccess);

            _loginSessionManager.UpdateLoginSessionWithRelation(sessionAndResponse);

            // Create a custom response object
            var responseBody = new
            {
                state = state,
                code = authorizationCode
            };

            // TODO: change for now
            HttpContext.Response.StatusCode = 200;
            // TODO: has error
            //HttpContext.Response.Headers.Append("state", state);

            // TODO: I don't know why if add "Location" as key in response header, the response will be sent in vuejs's web is with status code 200,
            //     : but if I modify the name, for example, to "Location1", then the response will has status code 302 as I set to it before...
            HttpContext.Response.Headers.Append("location", string.Format("{0}?code={1}", redirectUri, authorizationCode));
            // Serialize the custom response object to JSON and write it to the response body
            await HttpContext.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(responseBody));

            return new EmptyResult();
            // TODO: return to client authorization code, this code is one time to use
            //     : client will use token endpoint and send authorization code to get access token and id token
            //     : client can use access token to send request to user_info endpoint to get user info, but currently not implement this function

            // TODO: implement jwt access token instead of a string encoded with base64
            //     : https://datatracker.ietf.org/doc/html/rfc9068#JWTATLRequest

            //return StatusCode(200, authorizationCode);
        }

        private bool VerifyScope(string scope, PrMClient client)
        {
            scope = System.Uri.UnescapeDataString(scope);
            foreach (var s in scope.Split(" "))
            {
                if (!client.AllowedScopes.Contains(s))
                    return false;
            }
            return true;
        }

        private async Task<ActionResult> GetAccessTokenFromAuthorizationCodeAsync(Dictionary<string, string> requestBody)
        {
            // TODO: get from queryString, authorization code
            //     : get user along with authorization code inside latest login session (of that user)
            //     : create access token and id token, send it to client

            var webServerConfiguration = _configuration.GetSection(IdentityServerConfiguration.WEB_SERVER);

            string authorizationCode = requestBody[TokenRequest.Code];
            if (string.IsNullOrEmpty(authorizationCode))
                return StatusCode(400, "authorization code is missing!");

            // TODO: for now, every request, by default in scop will have openid, so ignore this part of checking now
            //     : Verify that the Authorization Code used was issued in response to an OpenID Connect Authentication Request(so that an ID Token will be returned from the Token Endpoint).
            var loginSession = _loginSessionManager.FindByAuthorizationCode(authorizationCode);

            // TODO: Authenticate the Client if it was issued Client Credentials or if it uses another Client Authentication method, per Section 9.
            //     : Ensure the Authorization Code was issued to the authenticated Client.
            if (loginSession == null)
                return StatusCode(500, "unknown");

            //Verify that the Authorization Code is valid.
            //If possible, verify that the Authorization Code has not been previously used.
            if (!loginSession.TokenRequestSession.IsInLoginSession)
                // TODO: status code may wrong
                return StatusCode(500, "login session is end!");

            string clientId = requestBody[TokenRequest.ClientId];
            string clientSecret = requestBody[TokenRequest.ClientSecret];
            if (string.IsNullOrEmpty(clientId)
                || string.IsNullOrEmpty(clientSecret))
                return StatusCode(400, "client credentials's info is missing!");

            var client = _clientDbServices.GetByIdAndSecret(clientId, clientSecret);
            if (!loginSession.TokenRequestSession.Client.Id.Equals(client.Id))
                // TODO: status code may wrong
                return StatusCode(400, "something wrong with client which Authorization Code was issued to!");

            //Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that was included in the initial Authorization Request.
            //If the redirect_uri parameter value is not present when there is only one registered redirect_uri value,
            //the Authorization Server MAY return an error(since the Client should have included the parameter) or MAY proceed without an error(since OAuth 2.0 permits the parameter to be omitted in this case).
            string[] redirectUris = client.RedirectUris.Split(",");
            var redirectUri = requestBody[TokenRequest.RedirectUri];
            if (!redirectUris.Contains(redirectUri))
                return StatusCode(400, "redirect_uri is mismatch!");

            // TODO: by default, those two go along together, it may wrong in future coding
            if (loginSession.TokenRequestSession.CodeChallenge != null && loginSession.TokenRequestSession.CodeChallengeMethod != null)
            {
                var codeVerifier = requestBody[TokenRequest.CodeVerifier];
                if (string.IsNullOrEmpty(codeVerifier))
                    return StatusCode(400, "code challenge is included in authorization code request but does not have in access token request!");

                var code_challenge = RNGCryptoServicesUltilities.Base64urlencodeNoPadding(codeVerifier.WithSHA265());
                if (!code_challenge.Equals(loginSession.TokenRequestSession.CodeChallenge))
                    return StatusCode(400, "code verifier is wrong!");
            }

            if (loginSession.TokenRequestSession.IsInLoginSession)
            {
                var user = _userDbServices.GetUserWithTokenResponse(loginSession.User.UserName);
                // TODO: get all login session belong to user with a particular client, but not other client
                var latestLoginSession = user.LoginSessionsWithResponse
                    .Where(l => l.TokenRequestSession != null && l.TokenRequestSession.Client.ClientId == clientId && l.TokenResponse != null)
                    .LastOrDefault();
                // TODO: at this step, need to check offline_access is inside authrization login request is true or fault
                //     : if fault, then response will not include refresh token
                //     : if true, then add refresh token along with response

                object responseBody = new object();

                if (latestLoginSession != null)
                {
                    //var tokenResponse = _loginSessionManager.CreateTokenResponse(latestLoginSession);
                    //var scope = HttpUtility
                    var id_token = GenerateIdToken(user, loginSession.TokenRequestSession.Scope, loginSession.TokenRequestSession.Nonce, client.ClientId);
                    bool isOfflineAccess = loginSession.TokenRequestSession.IsOfflineAccess;
                    if (isOfflineAccess)
                    {
                        // TODO: latest token response does not have refresh token
                        if (latestLoginSession.TokenResponse.RefreshTokenExpiried == null)
                        {
                            // TODO: latest access token can be used
                            if (latestLoginSession.TokenResponse.AccessTokenExpiried >= DateTime.Now)
                            {
                                var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                                string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                                string refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                                tokenResponse.AccessToken = access_token;
                                tokenResponse.IdToken = id_token;
                                tokenResponse.AccessTokenExpiried = latestLoginSession.TokenResponse.AccessTokenExpiried;
                                tokenResponse.RefreshToken = refresh_token;
                                tokenResponse.RefreshTokenExpiried = DateTime.Now.AddHours(4);

                                responseBody = CreateTokenResponseBody(tokenResponse.AccessToken, id_token,
                                    // TODO: count the remaining seconds which the access token can be usefull
                                    (latestLoginSession.TokenResponse.AccessTokenExpiried - DateTime.Now).Value.TotalSeconds,
                                    tokenResponse.RefreshToken);
                            }
                            // TODO: latest access token can not be re-used, expired
                            else
                            {
                                // TODO; if expired, create new
                                var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                                string refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                                tokenResponse.AccessToken = latestLoginSession.TokenResponse.AccessToken;
                                tokenResponse.IdToken = id_token;
                                tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                                tokenResponse.RefreshToken = refresh_token;
                                tokenResponse.RefreshTokenExpiried = DateTime.Now.AddHours(4);

                                responseBody = CreateTokenResponseBody(latestLoginSession.TokenResponse.AccessToken, id_token, 3600, tokenResponse.RefreshToken);
                            }
                        }
                        // TODO: latest token response has refresh token
                        else
                        {
                            // TODO: access token and refresh token can be re-used 
                            if (latestLoginSession.TokenResponse.AccessTokenExpiried >= DateTime.Now
                                && latestLoginSession.TokenResponse.RefreshTokenExpiried >= DateTime.Now)
                            {
                                responseBody = CreateTokenResponseBody(latestLoginSession.TokenResponse.AccessToken, id_token,
                                    // TODO: count the remaining seconds which the access token can be usefull
                                    (latestLoginSession.TokenResponse.AccessTokenExpiried - DateTime.Now).Value.TotalSeconds,
                                    latestLoginSession.TokenResponse.RefreshToken);
                            }
                            // TODO: has error in this part, but I will fix it later
                            // TODO: refresh token can be re-used, but not access token
                            else if (latestLoginSession.TokenResponse.AccessTokenExpiried < DateTime.Now
                                    && latestLoginSession.TokenResponse.RefreshTokenExpiried >= DateTime.Now)
                            {
                                var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                                string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                                tokenResponse.AccessToken = access_token;
                                tokenResponse.IdToken = id_token;

                                // TODO: access token expired time may over the refresh token expired time
                                TimeSpan diff = (TimeSpan)(latestLoginSession.TokenResponse.RefreshTokenExpiried - DateTime.Now);
                                if (diff.TotalSeconds < 3600)
                                    tokenResponse.AccessTokenExpiried = DateTime.Now.AddSeconds(diff.TotalSeconds);
                                else
                                    tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);

                                var refresh_token = latestLoginSession.TokenResponse.RefreshToken;
                                if (string.IsNullOrEmpty(refresh_token))
                                    refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                                tokenResponse.RefreshToken = refresh_token;
                                DateTime expiredIn = DateTime.Now;
                                if (latestLoginSession.TokenResponse.RefreshTokenExpiried != null)
                                {
                                    //TimeSpan diff = (TimeSpan)(latestLoginSession.TokenResponse.RefreshTokenExpiried - DateTime.Now);
                                    //double seconds = diff.TotalSeconds;

                                    //expiredIn.AddSeconds(seconds);
                                    expiredIn = latestLoginSession.TokenResponse.RefreshTokenExpiried.Value;
                                }

                                tokenResponse.RefreshTokenExpiried = expiredIn;

                                responseBody = CreateTokenResponseBody(tokenResponse.AccessToken, id_token, 3600, tokenResponse.RefreshToken);

                                loginSession.TokenResponse = tokenResponse;
                            }
                            // TODO: neither access token and refresh token cant be re-used
                            else if (latestLoginSession.TokenResponse.AccessTokenExpiried < DateTime.Now
                                && latestLoginSession.TokenResponse.RefreshTokenExpiried < DateTime.Now)
                            {
                                var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                                string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                                string refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                                tokenResponse.AccessToken = access_token;
                                tokenResponse.IdToken = id_token;
                                tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                                tokenResponse.RefreshToken = refresh_token;
                                tokenResponse.RefreshTokenExpiried = DateTime.Now.AddHours(4);

                                responseBody = CreateTokenResponseBody(access_token, id_token, 3600, refresh_token);
                            }
                            else if (latestLoginSession.TokenResponse.AccessTokenExpiried > DateTime.Now
                                && latestLoginSession.TokenResponse.RefreshTokenExpiried < DateTime.Now)
                            {
                                // TODO
                                var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                                string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                                string refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                                tokenResponse.AccessToken = access_token;
                                tokenResponse.IdToken = id_token;
                                tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                                tokenResponse.RefreshToken = refresh_token;
                                tokenResponse.RefreshTokenExpiried = DateTime.Now.AddHours(4);

                                responseBody = CreateTokenResponseBody(access_token, id_token, 3600, refresh_token);
                            }
                        }
                    }
                    else if (!isOfflineAccess)
                    {
                        if (latestLoginSession.TokenResponse.AccessTokenExpiried >= DateTime.Now)
                        {
                            responseBody = CreateTokenResponseBody(latestLoginSession.TokenResponse.AccessToken, id_token, 3600);
                        }
                        else
                        {
                            // TODO: re-authenticate
                            var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                            string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                            tokenResponse.AccessToken = access_token;
                            tokenResponse.IdToken = id_token;
                            tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                            loginSession.TokenResponse = tokenResponse;

                            responseBody = CreateTokenResponseBody(latestLoginSession.TokenResponse.AccessToken, id_token, 3600);
                        }
                    }

                    loginSession.TokenRequestSession.IsInLoginSession = false;
                    _loginSessionManager.UpdateInsideTokenResponse(loginSession);
                    _loginSessionManager.UpdateLoginSessionWithRelation(loginSession);

                    return Ok(JsonConvert.SerializeObject(responseBody));
                }
                else if (loginSession.TokenResponse == null)
                {
                    bool isOfflineAccess = loginSession.TokenRequestSession.IsOfflineAccess;
                    var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                    var id_token = GenerateIdToken(user, loginSession.TokenRequestSession.Scope, loginSession.TokenRequestSession.Nonce, client.ClientId);
                    string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                    tokenResponse.AccessToken = access_token;
                    tokenResponse.IdToken = id_token;

                    if (isOfflineAccess)
                    {
                        string refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                        tokenResponse.RefreshToken = refresh_token;
                        tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                        tokenResponse.RefreshTokenExpiried = DateTime.Now.AddHours(4);

                        responseBody = CreateTokenResponseBody(access_token, id_token, 3600, refresh_token);
                    }
                    else
                    {
                        responseBody = CreateTokenResponseBody(access_token, id_token, 3600);
                    }

                    loginSession.TokenResponse = tokenResponse;

                    loginSession.TokenRequestSession.IsInLoginSession = false;

                    // TODO: will check later
                    _loginSessionManager.UpdateInsideTokenResponse(loginSession);
                    _loginSessionManager.UpdateLoginSessionWithRelation(loginSession);

                    return Ok(JsonConvert.SerializeObject(responseBody));
                    // TODO: return access token and refresh token is empty if refresh token is still date
                    //     : create new access token, return along with refresh token has value if refresh token is expired
                }
            }

            return StatusCode(200);
        }

        private static object CreateTokenResponseBody(string access_token, string id_token, double expired_in, string refresh_token = "")
        {
            object responseBody;
            if (string.IsNullOrEmpty(refresh_token))
            {
                responseBody = new
                {
                    access_token = access_token,
                    id_token = id_token,
                    token_type = "Bearer",
                    // TODO: set by seconds
                    expires_in = expired_in
                };
            }
            else
                responseBody = new
                {
                    access_token = access_token,
                    id_token = id_token,
                    refresh_token = refresh_token,
                    token_type = "Bearer",
                    // TODO: set by seconds
                    expires_in = expired_in
                };

            return responseBody;
        }
        #endregion

        #region resiger user
        public async Task<ActionResult> RegisterUserAsync(string[] queryString, string state, string scope, string nonce, string redirectUri, string clientId)
        {
            try
            {
                var headers = HttpContext.Request.Headers;

                if (headers["Register"][0] == null)
                    return StatusCode(400, "Register header is missing!");

                queryString.GetFromQueryString("email", out string email);
                // TODO: for vietnamese text
                queryString.GetFromQueryString("name", out string name);
                name = HttpUtility.UrlDecode(name);
                queryString.GetFromQueryString("fullname", out string fullName);
                fullName = HttpUtility.UrlDecode(fullName);
                queryString.GetFromQueryString("gender", out string gender);
                queryString.GetFromQueryString("roles", out string roles);
                // TODO: will add role later

                // TODO: by default, I seperate the need of creating identity of someone with the flow of oauth2's authorization code flow 
                //     : but following specs, my implement maybe wrong, but I know it is optional or "more guideline" than "actual rules"
                scope = System.Uri.UnescapeDataString(scope);
                if (string.IsNullOrEmpty(scope))
                    return StatusCode(400, "scope is empty!");
                // TODO: nonce is optional, so may be string.empty

                var userCredentials = headers["Register"][0];
                var userNamePassword = (userCredentials.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, "").Trim()).ToBase64Decode();

                // TODO: will need to validate username and password, from client and server
                string userName = userNamePassword.Split(":")[0];
                string password = userNamePassword.Split(":")[1];

                if (string.IsNullOrEmpty(password))
                    return StatusCode(400, "password is missing!");

                var currentUser = _userDbServices.GetUserByUserName(userName);
                if (currentUser != null)
                    return StatusCode(409, "user with this username is already exist");

                // TODO: for test, I comment this part
                //if (!string.IsNullOrEmpty(email))
                //{
                //    var emailCheck = _userManager.FindByEmailAsync(email);
                //    if (currentUser != null)
                //        return StatusCode(409, "email can only be used for one account!");
                //}                

                var user = _userDbServices.InitiateUserWithRoles(userName, new string[] { }, email, name, fullName, gender);

                // TODO
                var result = _userManager.CreateAsync(user, password).Result;
                if (result.Succeeded)
                {
                    // TODO: https://openid.net/specs/openid-connect-prompt-create-1_0.html#name-authorization-request
                    var client = _clientDbServices.GetById(clientId);
                    var id_token = GenerateIdToken(user, scope, nonce, clientId);

                    if (!string.IsNullOrEmpty(user.Email))
                        await SendVerifyingEmailAsync(user, "ConfirmEmail", client);

                    object responseBody = new
                    {
                        status = 200,
                        message = "new user is created!",
                        id_token = id_token
                    };
                    if (!string.IsNullOrEmpty(state))
                    {
                        responseBody = new
                        {
                            status = 200,
                            message = "new user is created!",
                            state = state,
                            id_token = id_token
                        };
                    }

                    return StatusCode(200, responseBody);
                }
                else
                {
                    return StatusCode(500, "Internal server error!");
                }

            }
            catch (Exception ex)
            {
                return StatusCode(500, "Internal server error!");
            }
            //return StatusCode(500, "Unknown error!");
        }
        #endregion

        #region implicit grant
        /// <summary>
        /// TODO: not yet done
        /// </summary>
        /// <param name="requestQuerry"></param>
        /// <param name="responseMode"></param>
        /// <param name="redirectUri"></param>
        /// <param name="state"></param>
        /// <param name="scope"></param>
        /// <param name="nonce"></param>
        /// <param name="clientId"></param>
        /// <param name="headers"></param>
        /// <returns></returns>
        private async Task<ActionResult> ImplicitGrantWithFormPostAsync(string[] requestQuerry, string responseMode, string redirectUri, string state, string scope, string nonce, string clientId, IHeaderDictionary headers)
        {
            try
            {
                // TODO: for this situation, Thread and http context may not need
                //var principal = Thread.CurrentPrincipal;
                var principal = HttpContext.User;

                var user = await _userManager.GetUserAsync(principal);
                var client = _clientDbServices.GetById(clientId);
                scope = System.Uri.UnescapeDataString(scope);
                // TODO: scope is used for getting claims to send to client,
                //     : for example, if scope is missing email, then in id_token which will be sent to client will not contain email's information 
                var idToken = GenerateIdToken(user, scope, nonce, clientId);

                var loginSession = _loginSessionManager.CreateUserLoginSession(user, client);

                loginSession.TokenResponse.IdToken = idToken;

                // Check response mode to know what kind of response is going to be used
                // return a form_post, url fragment or body of response
                if (responseMode.Equals(ResponseModes.FormPost))
                {
                    Dictionary<string, string> inputBody = new Dictionary<string, string>();
                    inputBody.Add(AuthorizeResponse.IdentityToken, idToken);

                    //string formPost = GetFormPostHtml(webServerConfiguration["redirect_uris:0"], inputBody);
                    string formPost = GetFormPostHtml(redirectUri, inputBody);

                    HttpContext.Response.Headers.Append("state", state);

                    // TODO: will learn how to use this function
                    await WriteHtmlAsync(HttpContext.Response, formPost);

                    // TODO: will learn how to use it later
                    return new EmptyResult();
                }
                else if (responseMode.Equals(ResponseModes.Fragment))
                {
                    // TODO:
                }
                else if (responseMode.Equals(ResponseModes.Query))
                {
                    // TODO: will need to add state into response, return this form for now
                    return StatusCode(200, idToken);
                }
                else
                    return StatusCode(400, "Response mode is not allowed!");

            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }


            return StatusCode(200, "every thing is done!");
        }

        /// <summary>
        /// TODO: from duende
        /// </summary>
        /// <param name="formPost"></param>
        /// <returns></returns>
        private async Task WriteHtmlAsync(HttpResponse response, string formPost)
        {
            response.ContentType = "text/html; charset=UTF-8";
            await response.WriteAsync(formPost, Encoding.UTF8);
            await response.Body.FlushAsync();
        }


        /// <summary>
        /// From identityserver4
        /// </summary>
        private const string FormPostHtml = "<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head><body><form method='post' action='{uri}'>{body}<noscript><button>Click to continue</button></noscript></form><script>window.addEventListener('load', function(){document.forms[0].submit();});</script></body></html>";

        /// <summary>
        /// From identityserver4
        /// </summary>
        /// <param name="redirectUri"></param>
        /// <param name="inputBody"></param>
        /// <returns></returns>
        private string GetFormPostHtml(string redirectUri, Dictionary<string, string> inputBody)
        {
            var html = FormPostHtml;

            var url = redirectUri;
            url = HtmlEncoder.Default.Encode(url);
            html = html.Replace("{uri}", url);
            html = html.Replace("{body}", ToFormPost(inputBody));

            return html;
        }

        private string ToFormPost(Dictionary<string, string> collection)
        {
            var builder = new StringBuilder(128);
            const string inputFieldFormat = "<input type='hidden' name='{0}' value='{1}' />\n";

            foreach (var keyValue in collection)
            {
                var value = keyValue.Value;
                //var value = value;
                value = HtmlEncoder.Default.Encode(value);
                builder.AppendFormat(inputFieldFormat, keyValue.Key, value);
            }

            return builder.ToString();
        }
        #endregion

        [HttpGet("token")]
        // TODO: by oauth flow, only client can use this 
        [Authorize]
        // 5.3.2.  Successful UserInfo Response: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        public async Task<ActionResult> TokenEndpointAsync()
        {
            // TODO
            return StatusCode(200);
        }

        // TODO: try to implement from
        //     : https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/
        //     : Token Request Validation: https://openid.net/specs/openid-connect-core-1_0.html
        //     : only allow authorization code to get access token and id token,
        //     : access token will be use for scope uri, like userinfo or email...
        [HttpPost("token")]
        [AllowAnonymous]
        public async Task<ActionResult> TokenEndpointPostAsync()
        {
            // TODO: for now, only response to authorization code request to access token
            //     : need to implement another action
            //     : send back access_token when have request refresh 
            //if (!string.IsNullOrEmpty(HttpContext.Request.QueryString.Value))
            //    return StatusCode(400, "querry string must have for token request!");

            //var requestQuerry = HttpContext.Request.QueryString.Value.Remove(0, 1).Split("&");

            Dictionary<string, string> requestBody = new Dictionary<string, string>();

            using (StreamReader reader = new StreamReader(HttpContext.Request.Body))
            {
                var temp = await reader.ReadToEndAsync();
                temp.Split('&').ToList().ForEach(t =>
                {
                    var r = t.Split("=");
                    requestBody.Add(r[0], r[1]);
                });
            }

            if (requestBody.Count == 0)
                return StatusCode(400, "body is missing!");

            //string refreshToken = requestBody.FirstOrDefault(c => c.StartsWith(GrantTypes.RefreshToken)).Split("=")[1];
            string grantType = requestBody[TokenRequest.GrantType];

            switch (grantType)
            {
                case OidcConstants.GrantTypes.RefreshToken:
                    {
                        // TODO: return new accesstoken using refresh token if it's not expired
                        var loginSessionWithToken = _loginSessionManager.FindByRefreshToken(grantType);

                        return StatusCode(500, "not implement exception!");
                    }
                case OidcConstants.GrantTypes.AuthorizationCode:
                    return await GetAccessTokenFromAuthorizationCodeAsync(requestBody);
                default:
                    return StatusCode(500, "Unknown error!");
            }
        }

        // TODO: by oauth flow, need access token to be verified before using this function
        //     : done using access token, verify with authorization: bearer
        [HttpGet("userinfo")]
        [Authorize]
        public async Task<ActionResult> GetUserInfoAsync()
        {
            // TODO: exchange access token to get user from latest login session inside memory
            //     : create user_info json response to send to client

            // By using [Authorize], in this step, user in httpcontext must be set before this
            var userClaims = HttpContext.User;

            // TODO: create authorization code
            //var authorizationCode = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(32);
            // TODO: by using authorization before this part, so it should has an user in HttpContext
            var user = await _userManager.GetUserAsync(userClaims);

            var responseBody = new
            {
                sub = user.UserName,
                name = user.FullName,
                //given_name = user.name,
                //family_name = "Doe",
                //preferred_username = "j.doe",
                email = user.Email,
                email_confirmed = user.IsEmailConfirmed,
                picture = user.Avatar
            };

            return StatusCode(200, JsonConvert.SerializeObject(responseBody));
        }

        [HttpGet("userinfo.email")]
        // TODO: by oauth flow, need access token to be verified before using this function
        [Authorize]
        public async Task<ActionResult> GetUserInfoAndEmailAsync()
        {
            // TODO: exchange access token to get user from latest login session inside memory
            //     : create user_info json response to send to client

            return StatusCode(200);
        }

        private string GetDefaultResponseModeByResponseType(string responseType)
        {
            string responseMode = "";

            if (!string.IsNullOrEmpty(responseType))
            {
                // get grant type for response type
                string grantType = Constants.ResponseTypeToGrantTypeMapping[responseType];
                // map grant type with allowed response mode
                string[] responseModes = Constants.AllowedResponseModesForGrantType[grantType].ToArray();

                // TODO: by default
                if (responseType.Equals(OidcConstants.ResponseTypes.Code))
                    responseMode = responseModes.First(m => m.Equals(OidcConstants.ResponseModes.Query));
                else if (responseType.Equals(OidcConstants.ResponseTypes.Token))
                    responseMode = responseModes.First(m => m.Equals(OidcConstants.ResponseModes.Fragment));

            }

            return responseMode;
        }

        /// <summary>
        /// authorization_endpoint
        /// </summary>
        /// <returns></returns>
        [HttpPost("authorize")]
        public async Task<ActionResult> AuthorizationPostAsync()
        {
            // 1. Get authorization request from server
            // 2. Return an http 302 message to server, give it a nonce cookie (for now, ignore this part),
            //    if asking for google, then send a redirect to google to get authorization code
            //    if basic access, then return a redirect to another request to identity server - send request to "authentication/basicAccess" route
            // 3.

            return StatusCode(200);
        }

        /// <summary>
        /// TODO: will verify this function later
        /// </summary>
        /// <returns></returns>
        [HttpGet("ConfirmEmail")]
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmailAsync()
        {
            try
            {
                if (!HttpContext.Request.QueryString.HasValue)
                    return StatusCode(400, "query_string_is_mismatch!");

                var query = HttpContext.Request.Query;
                var userId = int.Parse(query["userId"]);
                var code = query["code"];

                // TODO:
                //var user = _userDbServices.GetUserWithRelation(userId);
                ////var user = _userDbServices.GetUserIncludeConfirmEmail(userId);
                //if (!user.ConfirmEmail.ConfirmCode.Equals(code))
                //    return StatusCode(404, "Confirm code is not match!");
                //if (!(user.ConfirmEmail.ExpiryTime > DateTime.Now))
                //    return StatusCode(400, "Confirm code is expired!");
                //if (user.ConfirmEmail.IsConfirmed == true)
                //    return StatusCode(200, "Email is confirmed!");
                //else
                //{
                //    user.IsEmailConfirmed = true;
                //    user.ConfirmEmail.IsConfirmed = true;
                //}

                //_userDbServices.SaveChanges();
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
            return StatusCode(200, "Email is confirmed!");
        }

        #region Google authentication
        //[HttpPost("v{version:apiVersion}/authorize/google")]
        [HttpGet("authorize/google")]
        // TODO: comment for now, but when everything is done, this policy must be used, 
        //     : only identityserver's clients can use this endpoint, not user-agent
        //[Authorize(Roles = "Client")]
        public async Task<ActionResult> GoogleAuthenticating()
        {
            var googleClientConfig = _configuration.GetSection(IdentityServerConfiguration.GOOGLE_CLIENT);

            string clientID = googleClientConfig[IdentityServerConfiguration.CLIENT_ID];
            string clientSecret = googleClientConfig[IdentityServerConfiguration.CLIENT_SECRET];
            string authorizationEndpoint = googleClientConfig[IdentityServerConfiguration.AUTHORIZATION_ENDPOINT];
            string tokenEndpoint = googleClientConfig[IdentityServerConfiguration.TOKEN_ENDPOINT];
            string[] redirectUris = googleClientConfig.GetSection(IdentityServerConfiguration.REDIRECT_URIS).Get<string[]>();

            if (googleClientConfig == null
                || string.IsNullOrEmpty(clientID)
                || string.IsNullOrEmpty(clientSecret)
                || string.IsNullOrEmpty(authorizationEndpoint)
                || string.IsNullOrEmpty(tokenEndpoint)
                || redirectUris == null || redirectUris.Length == 0)
                return StatusCode(500);

            //string projectId = googleClientConfiguration[IdentityServerConfiguration.PROJECT_ID];
            //string userInfoEndpoint = "https://www.googleapis.com/oauth2/userinfo";

            if (!HttpContext.Request.QueryString.HasValue)
                return StatusCode(400, "Query string of google authenticate request must have value!");

            var queryString = HttpContext.Request.QueryString.Value.Remove(0, 1).Split("&");
            queryString.GetFromQueryString("code", out string authorizationCode);
            if (authorizationCode == null)
                return StatusCode(400, "authorization code does not included!");

            var requestHeaders = HttpContext.Request.Headers;

            var redirectUri = requestHeaders["redirect_uri"];
            var codeVerifier = requestHeaders["code_verifier"];
            if (string.IsNullOrEmpty(redirectUris.FirstOrDefault(r => r.Equals(HttpUtility.UrlDecode(redirectUri)))))
                return StatusCode(400, "redirect_uri_mismatch!");

            if (string.IsNullOrEmpty(codeVerifier))
                return StatusCode(400, "code_verifier_mismatch!");

            // builds the  request
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code",
                authorizationCode,
                redirectUri,
                clientID,
                codeVerifier,
                clientSecret);

            // sends the request
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenEndpoint);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            string id_token = "";
            string user_info = "";
            try
            {
                // gets the response
                WebResponse tokenResponse = await tokenRequest.GetResponseAsync();

                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    // reads response body
                    string responseText = await reader.ReadToEndAsync();
                    //output(responseText);

                    // TODO: because I will send nonce to google, that was created by web server and send to my identity server, so need to check nonce from google to prevent id_token inject.

                    // converts to dictionary
                    Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                    string access_token = tokenEndpointDecoded["access_token"];
                    id_token = tokenEndpointDecoded["id_token"];

                    // TODO: validate at_hash from id_token is OPTIONAL in some flows (hybrid flow,...),
                    //     : I will check when to implement it later, now, better it has than it doesn't
                    //     : comment for now
                    //ValidateAtHash(id_token, access_token);

                    // TODO: will learn how to use it, comment for now
                    //GoogleJsonWebSignature.Payload payload = await GoogleJsonWebSignature.ValidateAsync(id_token);
                    user_info = userinfoCall(access_token).Result;
                }

                // TODO: will need to create new user if current user with this email is not have
                //     : after that, create login session object and save to db
                //     : after create login session, authentication then will perform
            }
            catch (WebException ex)
            {
                //if (ex.Status == WebExceptionStatus.ProtocolError)
                //{
                //    var response = ex.Response as HttpWebResponse;
                //    if (response != null)
                //    {
                //        //output("HTTP: " + response.StatusCode);
                //        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                //        {
                //            // reads response body
                //            string responseText = await reader.ReadToEndAsync();
                //            //output(responseText);
                //        }
                //    }

                //}
            }

            return Ok(user_info);
        }

        /// <summary>
        /// TODO: validate at_hash from id_token is OPTIONAL in some flow,
        ///     : I will check when to implement it later, now, better it has than it doesn't
        ///     https://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
        ///     and https://stackoverflow.com/questions/30356460/how-do-i-validate-an-access-token-using-the-at-hash-claim-of-an-id-token
        /// </summary>
        /// <param name="id_token"></param>
        /// <param name="access_token"></param>
        private bool ValidateAtHash(string id_token, string access_token)
        {
            JwtSecurityToken idTokenAsClaims = DecodeIdTokenString(id_token);

            var alg = idTokenAsClaims.Header["alg"];
            var at_hash = idTokenAsClaims.Claims.FirstOrDefault(c => c.Type.Equals("at_hash"));
            if (alg.Equals("RS256"))
            {
                if (at_hash != null && at_hash.Value != null)
                {
                    // TODO: verify access token
                    using (SHA256 hashProtocol = SHA256.Create())
                    {
                        byte[] accessTokenAsEncodeBytes = hashProtocol.ComputeHash(Encoding.ASCII.GetBytes(access_token));
                        byte[] firstHalf = accessTokenAsEncodeBytes.Take(accessTokenAsEncodeBytes.Length / 2).ToArray();

                        var checkPoint = RNGCryptoServicesUltilities.Base64urlencodeNoPadding(firstHalf);

                        return at_hash.Value.Equals(checkPoint);
                    }
                }
            }

            return false;
        }

        private JwtSecurityToken DecodeIdTokenString(string id_token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(id_token);
            return jwtSecurityToken;
        }

        async Task<string> userinfoCall(string access_token)
        {
            string output = "";
            // builds the  request
            string userinfoRequestURI = "https://www.googleapis.com/oauth2/v3/userinfo";

            // sends the request
            HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userinfoRequestURI);
            userinfoRequest.Method = "GET";
            userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
            userinfoRequest.ContentType = "application/x-www-form-urlencoded";
            userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            // gets the response
            WebResponse userinfoResponse = await userinfoRequest.GetResponseAsync();
            using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
            {
                // reads response body
                string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
                //output(userinfoResponseText);
                output = userinfoResponseText;
            }

            return output;
        }
        #endregion

        #region update user
        [HttpPost("user/update")]
        [Authorize]
        public async Task<ActionResult> UpdateUserAsync()
        {
            var userClaims = HttpContext.User;

            var user = await _userManager.GetUserAsync(userClaims);

            // TODO: will check again
            if (user == null)
                return StatusCode(500, "error!");
            if (user.IsEmailConfirmed == true)
                return StatusCode(400, "user's email is already confirmed!");

            //return await SendVerifyingEmailAsync(user, "updateUser", client);
            return Ok();
        }
        #endregion

        #region forget password
        [HttpPost("user/forgotPassword")]
        [AllowAnonymous]
        public async Task<ActionResult> ForgotPasswordPost()
        {

            Dictionary<string, string> requestBody = new Dictionary<string, string>();

            using (StreamReader reader = new StreamReader(HttpContext.Request.Body))
            {
                var temp = await reader.ReadToEndAsync();
                requestBody = JsonConvert.DeserializeObject<Dictionary<string, string>>(temp);
                //temp.Split('&').ToList().ForEach(t =>
                //{
                //    var r = t.Split("=");
                //    requestBody.Add(r[0], r[1]);
                //});
            }

            // TODO: get from query string, code, new password, 
            var queryString = HttpContext.Request.QueryString.Value;
            if (queryString == null)
                return StatusCode(400, "query is missing!");
            var queryBody = queryString.Remove(0, 1).Split("&");

            //queryBody.GetFromQueryString("code", out string code);
            var code = requestBody["code"];
            if (string.IsNullOrEmpty(code))
                return StatusCode(400, "forgot password verifying code is missing!");
            //queryBody.GetFromQueryString("password", out string password);
            var password = requestBody["password"];
            if (string.IsNullOrEmpty(password))
                return StatusCode(400, "new password is missing!");
            queryBody.GetFromQueryString(JwtClaimTypes.ClientId, out string clientId);
            if (string.IsNullOrEmpty(clientId))
                return StatusCode(400, "client id is missing!");

            var confirmEmail = _emailDbServices.GetByCode(code);
            if (!confirmEmail.Purpose.Equals((int)ConfirmEmailPurpose.ChangePassword))
                return StatusCode(500, "something inside this process is wrong!");
            if (confirmEmail.ExpiryTime.HasValue || confirmEmail.ExpiryTime < DateTime.Now)
                return StatusCode(500, "error with email's expired time!");

            var user = confirmEmail.User;
            try
            {
                var ir = _userManager.RemovePasswordAsync(user).Result;
                var nir = _userManager.AddPasswordAsync(user, password).Result;
                confirmEmail.IsConfirmed = true;
                _emailDbServices.Update(confirmEmail);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }

            return Ok();
        }

        [HttpGet("user/forgotPassword")]
        [AllowAnonymous]
        public async Task<ActionResult> ForgotPassword()
        {
            try
            {
                var queryString = HttpContext.Request.QueryString.Value;
                if (queryString == null)
                    return StatusCode(400, "query is missing!");
                var queryBody = queryString.Remove(0, 1).Split("&");

                queryBody.GetFromQueryString(JwtClaimTypes.ClientId, out string clientId);
                if (string.IsNullOrEmpty(clientId))
                    return StatusCode(400, "client id is missing!");
                queryBody.GetFromQueryString(JwtClaimTypes.Email, out string email);
                if (string.IsNullOrEmpty(email))
                    return StatusCode(400, "email is missing!");

                var client = _clientDbServices.GetById(clientId);
                if (client == null)
                    return StatusCode(404, "client id may wrong!");

                // TODO: get user by email, by logic, username + email is unique for an user that is stored in db, but fow now, email may be duplicated for test
                var user = _userManager.Users.FirstOrDefault(u => u.Email.Equals(email));
                await SendForgotPasswordCodeToEmail(user, client);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
            return Ok();
        }

        private async Task<ActionResult> SendForgotPasswordCodeToEmail(PrMUser user, PrMClient client)
        {
            var code = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(8);
            //var sr = _userManager.get
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            int expiredTimeInMinutes = 1;
            await CreateConfirmEmailAsync(user, code, client, ConfirmEmailPurpose.ChangePassword, expiredTimeInMinutes);

            string emailBody = $"Your password reset's security code is <span style=\"font-weight:bold; font-size:25px\">{code}</span>.";
            SendEmail(user, emailBody);

            return Ok();
        }
        #endregion

        private async Task<ActionResult> SendVerifyingEmailAsync(PrMUser user, string callbackEndpoint, PrMClient client)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //var sr = _userManager.get
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            int expiredTimeInMinutes = 60;
            await CreateConfirmEmailAsync(user, code, client, ConfirmEmailPurpose.CreateIdentity, expiredTimeInMinutes);

            string callbackUrl = string.Format("{0}?area=Identity&userId={1}&code={2}",
                   $"{Request.Scheme}://{Request.Host}/oauth2/{callbackEndpoint}",
                   user.Id,
                   code);
            string emailBody = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.";
            SendEmail(user, emailBody);

            return Ok();
        }

        private bool SendEmail(PrMUser user, string emailBody)
        {
            bool result = true;
            try
            {
                var email = new MimeMessage();
                email.From.Add(new MailboxAddress(_mailSettings.Name, _mailSettings.EmailId));
                // TODO: test email for now
                email.To.Add(new MailboxAddress(user.UserName, user.Email));

                email.Subject = "Testing out email sending";
                // $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");
                email.Body = new TextPart(MimeKit.Text.TextFormat.Html)
                {
                    //Text = $"<b>Hello all the way from the land of C# {callbackUrl}</b>"
                    Text = emailBody
                };

                using (var smtp = new SmtpClient())
                {
                    smtp.Connect(_mailSettings.Host, 587, false);

                    // Note: only needed if the SMTP server requires authentication
                    smtp.Authenticate(_mailSettings.EmailId, _mailSettings.Password);

                    smtp.Send(email);
                    smtp.Disconnect(true);
                }
            }
            catch (Exception)
            {
                result = false;
            }

            return result;
        }

        private async Task CreateConfirmEmailAsync(PrMUser user, string code, PrMClient client, ConfirmEmailPurpose purpose, int expiredTimeInMinutes)
        {
            try
            {
                var nw = _emailDbServices.CreateWithoutSaveChanges();
                nw.ConfirmCode = code;
                nw.User = user;
                nw.Client = client;
                nw.Purpose = (int)purpose;
                nw.IsConfirmed = false;
                nw.ExpiryTime = DateTime.Now.AddMinutes(expiredTimeInMinutes);
                nw.CreatedTime = DateTime.Now;

                if (_emailDbServices.Create(nw))
                {

                }

            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// TODO: try to implement from https://datatracker.ietf.org/doc/html/rfc9068
        ///     : and https://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private string GenerateAccessToken(PrMUser user)
        {
            return string.Empty;
        }

        // To generate token
        /// <summary>
        /// https://openid.net/specs/openid-connect-core-1_0.html
        /// 3.1.3.7.  ID Token Validation
        /// </summary>
        /// <param name="user"></param>
        /// <param name="scopeStr"></param>
        /// <param name="nonce"></param>
        /// <param name="client"></param>
        /// <returns></returns>
        private string GenerateIdToken(PrMUser user, string scopeStr, string nonce, string clientid)
        {
            try
            {
                // TODO: use rsa256 instead of hs256 for now
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                //var rsa = RSA.Create(2048);
                //var keygen = new SshKeyGenerator.SshKeyGenerator(2048);
                //var privateKey = keygen.ToPrivateKey();
                //Console.WriteLine(privateKey);

                //var publicSshKey = keygen.ToRfcPublicKey();
                //Console.WriteLine(publicSshKey);

                //rsa.ImportRSAPrivateKey(Convert.FromBase64String(_configuration["Jwt:Key"]), out _);
                //RsaSecurityKey key = new RsaSecurityKey(rsa);
                //var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
                //var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                var scopes = scopeStr.Split(" ");

                var claims = new List<Claim>();

                if (scopes.Contains(IdentityServerConstants.StandardScopes.OpenId))
                {
                    claims.Add(new Claim(JwtClaimTypes.Subject, user.UserName));
                    claims.Add(new Claim(JwtClaimTypes.Audience, clientid));
                    // TODO: hard code for now
                    claims.Add(new Claim(JwtClaimTypes.Issuer, System.Uri.EscapeDataString("https://localhost:7180")));
                }
                if (scopes.Contains(IdentityServerConstants.StandardScopes.Profile))
                {
                    // TODO: will add more
                    claims.Add(new Claim(JwtClaimTypes.Name, user.FullName));
                    //claims.Add(new Claim("username", user.UserName));
                    claims.Add(new Claim(JwtClaimTypes.Gender, user.Gender));
                    claims.Add(new Claim(JwtClaimTypes.UpdatedAt, user.UpdateTime.ToString()));
                    claims.Add(new Claim(JwtClaimTypes.Picture, user.Avatar));
                    claims.Add(new Claim(JwtClaimTypes.BirthDate, user.DateOfBirth.ToString()));
                    //claims.Add(new Claim(JwtClaimTypes.Locale, user.lo))
                }
                if (scopes.Contains(IdentityServerConstants.StandardScopes.Email))
                {
                    claims.Add(new Claim(JwtClaimTypes.Email, user.Email));
                    claims.Add(new Claim(JwtClaimTypes.EmailVerified, user.IsEmailConfirmed.ToString()));
                }
                if (scopes.Contains(IdentityServerConstants.StandardScopes.Phone))
                {
                    claims.Add(new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber));
                }
                // TOOD: will add later
                if (scopes.Contains(Constants.CustomScope.Role))
                {
                    user.PrMIdentityUserRoles.ToList().ForEach(p =>
                    {
                        claims.Add(new Claim(JwtClaimTypes.Role, p.Role.RoleName));
                    });
                }

                if (!string.IsNullOrEmpty(nonce))
                    claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));


                var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
                    _configuration["Jwt:Audience"],
                    claims,
                    expires: DateTime.Now.AddMinutes(15),
                    signingCredentials: credentials);

                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        private T Cast<T>(object obj, T model)
        {
            return (T)obj;
        }
    }
}
