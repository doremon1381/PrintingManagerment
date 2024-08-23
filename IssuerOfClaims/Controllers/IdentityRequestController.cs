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
using Azure.Core;
using Google.Apis.Auth.OAuth2.Responses;

namespace IssuerOfClaims.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //[ApiVersion("1.0")]
    [ControllerName("oauth2")]
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
        public async Task<ActionResult> Authorization()
        {
            // 1. Get authorization request from server
            // 2. Return an http 302 message to server, give it a nonce cookie (for now, ignore this part),
            //    if asking for google, then send a redirect to google to get authorization code
            //    if basic access (I mean implicit grant - form_post or not), then return a redirect to another request to identity server - send request to "authentication/basicAccess" route
            // 3.

            var webServerConfiguration = _configuration.GetSection(IdentityServerConfiguration.WEB_SERVER);
            string[] redirectUris = webServerConfiguration.GetSection(IdentityServerConfiguration.REDIRECT_URIS).Get<string[]>();

            // TODO: why code is not included in request's header,
            //     : because I like it to be include in query's string!
            if (!HttpContext.Request.QueryString.HasValue)
                return StatusCode(400, "Request must containt query string for authorization!");

            var requestQuerry = HttpContext.Request.QueryString.Value.Remove(0, 1).Split("&");

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

            // TODO: because in implicit grant flow, redirectUri is use to redirect to user-agent, 
            //     : in logically, client does not know it before user-agent send a redirect_uri to client
            //     : with browser's work, I think many browser can be user-agent, so it will be safe when client asks for redirect_uri from user-agent
            requestQuerry.GetFromQueryString(AuthorizeRequest.RedirectUri, out string redirectUri);
            redirectUri = System.Uri.UnescapeDataString(redirectUri);
            if (string.IsNullOrEmpty(redirectUri))
                return StatusCode(400, "Redirect uri is need for send a response back to where it needs!");
            if (!redirectUris.Contains(redirectUri))
                return StatusCode(400, "redirectUri is mismatch!");

            // TODO: try to add nonce in flow, will check it late
            //     : because "nonce" still OPTIONAL in some case, so I will use it when it's provided for identity server
            requestQuerry.GetFromQueryString(AuthorizeRequest.Nonce, out string nonce);
            // TODO: try to add nonce in flow, will check it late
            //     : because "state" still RECOMMENDED in some case, so I will use it when it's provided for identity server
            requestQuerry.GetFromQueryString(AuthorizeRequest.State, out string state);
            //if (string.IsNullOrEmpty(state))
            //    return StatusCode(400, "State of request must be implemented to avoid cross-site request forgery!");

            // TODO: need to compare with existing client in memory or database
            requestQuerry.GetFromQueryString(AuthorizeRequest.ClientId, out string clientId);
            if (string.IsNullOrEmpty(clientId))
                return StatusCode(400, "client id is mismatch!");

            //TODO: base on scope, I will add claims in id token, so it will need to be verified with client's scope in memory or database
            //    : Verify that a scope parameter is present and contains the openid scope value.
            //    : (If no openid scope value is present, the request may still be a valid OAuth 2.0 request but is not an OpenID Connect request.)
            requestQuerry.GetFromQueryString(AuthorizeRequest.Scope, out string scope);
            if (string.IsNullOrEmpty(scope))
                return StatusCode(ProtectedResourceErrors.InsufficientScope.StatusCodeWithError(), ProtectedResourceErrors.InsufficientScope);

            // TODO: from https://openid.net/specs/openid-connect-prompt-create-1_0.html
            //     : When the prompt parameter is used in an authorization request to the authorization endpoint with the value of create,
            //     : it indicates that the user has chosen to be shown the account creation experience rather than the login experience
            requestQuerry.GetFromQueryString(AuthorizeRequest.Prompt, out string prompt);

            var headers = HttpContext.Request.Headers;

            // https://openid.net/specs/openid-connect-prompt-create-1_0.html
            // TODO: validate propmt need to wait
            if (!string.IsNullOrEmpty(prompt)
                && prompt.Equals("create"))
            {
                return await RegisterUser(state);
            }
            else
            {
                if (scope.Contains(IdentityServerConstants.StandardScopes.OpenId))
                    switch (responseType)
                    {
                        case ResponseTypes.Code:
                            return await AuthorizationCodeFlow(requestQuerry, responseMode, redirectUri, state, scope, nonce, clientId, headers);
                        //break;
                        case ResponseTypes.IdToken:
                            return await ImplicitGrantWithFormPost(requestQuerry, responseMode, redirectUri, state, scope, nonce, clientId, headers);
                        //break;
                        // TODO: will implement another flow if I have time
                        default:
                            break;
                    }
                else
                {
                    // TODO: if in scope doesnot have openid, it still valid in some case but it's not an Authentication Request that use Oauth2 as standard
                }
            }

            return StatusCode(500, "Not yet know why...");
        }

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
        private async Task<ActionResult> AuthorizationCodeFlow(string[] requestQuerry, string responseMode, string redirectUri, string state, string scope, string nonce, string clientId, IHeaderDictionary headers)
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
            scope = System.Uri.UnescapeDataString(scope);
            if (!client.AllowedScopes.Contains(scope))
                return StatusCode(400, "scope is not allowed!");

            // TODO: add authorization code to loginSession
            // TODO: set loginSession info
            var sessionAndResponse = _loginSessionManager.CreateUserLoginSession(user, client);

            requestQuerry.GetFromQueryString(AuthorizeRequest.CodeChallenge, out string codeChallenge);
            requestQuerry.GetFromQueryString(AuthorizeRequest.CodeChallengeMethod, out string codeChallengeMethod);
            requestQuerry.GetFromQueryString("client_state", out string clientState);

            sessionAndResponse.LoginSession.CodeChallengeMethod = codeChallengeMethod;
            sessionAndResponse.LoginSession.CodeChallenge = codeChallenge;
            sessionAndResponse.LoginSession.AuthorizationCode = authorizationCode;
            sessionAndResponse.LoginSession.Nonce = nonce;
            sessionAndResponse.LoginSession.ClientState = clientState;
            sessionAndResponse.LoginSession.Scope = scope;
            sessionAndResponse.LoginSession.IsOfflineAccess = scope.Contains(StandardScopes.OfflineAccess);

            _loginSessionManager.UpdateLoginSessionWithRelation(sessionAndResponse);

            // Create a custom response object
            var responseBody = new
            {
                status = 302,
                state = state,
                code = authorizationCode
            };

            HttpContext.Response.StatusCode = 302;
            // TODO: has error
            //HttpContext.Response.Headers.Append("state", state);

            // TODO: I don't know why if add "Location" as key in response header, the response will be sent in vuejs's web is with status code 200,
            //     : but if I modify the name, for example, to "Location1", then the response will has status code 302 as I set to it before...
            HttpContext.Response.Headers.Append("IdentityLocation", string.Format("{0}?client_state={1}&code={2}", redirectUri, clientState, authorizationCode));
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
        private async Task<ActionResult> ImplicitGrantWithFormPost(string[] requestQuerry, string responseMode, string redirectUri, string state, string scope, string nonce, string clientId, IHeaderDictionary headers)
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
                var idToken = GenerateIdToken(user, scope, nonce, client);

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

        [HttpGet("token")]
        // TODO: by oauth flow, only client can use this 
        [Authorize]
        // 5.3.2.  Successful UserInfo Response: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        public async Task<ActionResult> TokenEndpoint()
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
        public async Task<ActionResult> TokenEndpointPost()
        {
            // TODO: for now, only response to authorization code request to access token
            //     : need to implement another action
            //     : send back access_token when have request refresh 
            //if (!string.IsNullOrEmpty(HttpContext.Request.QueryString.Value))
            //    return StatusCode(400, "querry string must have for token request!");

            //var requestQuerry = HttpContext.Request.QueryString.Value.Remove(0, 1).Split("&");

            //requestQuerry.GetFromQueryString(TokenRequest.GrantType, out string grantType);
            //if (string.IsNullOrEmpty(grantType))
            //    return StatusCode(400, "grant type is missing!");

            //requestQuerry.GetFromQueryString(GrantTypes.RefreshToken, out string refreshToken);
            //if (string.IsNullOrEmpty(refreshToken))
            //    return StatusCode(400, "refreshToken is missing!");

            string[] requestBody = new string[] { };

            using (StreamReader reader = new StreamReader(HttpContext.Request.Body))
            {
                var temp = await reader.ReadToEndAsync();
                requestBody = temp.Split('&');
            }

            if (requestBody.Length == 0)
                return StatusCode(400, "body is missing!");

            //string refreshToken = requestBody.FirstOrDefault(c => c.StartsWith(GrantTypes.RefreshToken)).Split("=")[1];
            string grantType = requestBody.FirstOrDefault(c => c.StartsWith(TokenRequest.GrantType)).Split("=")[1];

            switch (grantType)
            {
                case GrantTypes.RefreshToken:
                    {
                        var loginSessionWithToken = _loginSessionManager.FindByRefreshToken(grantType);

                        return StatusCode(500, "not implement exception!");
                    }
                case GrantTypes.AuthorizationCode:
                    return await GetAccessTokenFromAuthorizationCode(requestBody);
                default:
                    return StatusCode(500, "Unknown error!");
            }
        }

        private async Task<ActionResult> GetAccessTokenFromAuthorizationCode(string[] requestBody)
        {
            // TODO: get from queryString, authorization code
            //     : get user along with authorization code inside latest login session (of that user)
            //     : create access token and id token, send it to client

            var webServerConfiguration = _configuration.GetSection(IdentityServerConfiguration.WEB_SERVER);

            // TODO: why code is not included in request's header,
            //     : because I like it to be include in query's string!
            //if (!HttpContext.Request.QueryString.HasValue)
            //    return StatusCode(400, "Request must containt query string for authorization!");

            //var requestQuerry = HttpContext.Request.QueryString.Value.Remove(0, 1).Split("&");
            //var content = HttpContext.Request.BodyReader.ReadAsync().Result;

            string authorizationCode = requestBody.FirstOrDefault(c => c.StartsWith(TokenRequest.Code)).Split("=")[1];
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
            if (!loginSession.LoginSession.IsInLoginSession)
                // TODO: status code may wrong
                return StatusCode(500, "login session is end!");

            string clientId = requestBody.FirstOrDefault(c => c.StartsWith(TokenRequest.ClientId)).Split("=")[1];
            string clientSecret = requestBody.FirstOrDefault(c => c.StartsWith(TokenRequest.ClientSecret)).Split("=")[1];
            if (string.IsNullOrEmpty(clientId)
                || string.IsNullOrEmpty(clientSecret))
                return StatusCode(400, "client credentials's info is missing!");

            var client = _clientDbServices.GetByIdAndSecret(clientId, clientSecret);
            if (!loginSession.LoginSession.Client.Id.Equals(client.Id))
                // TODO: status code may wrong
                return StatusCode(400, "something wrong with client which Authorization Code was issued to!");

            //Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that was included in the initial Authorization Request.
            //If the redirect_uri parameter value is not present when there is only one registered redirect_uri value,
            //the Authorization Server MAY return an error(since the Client should have included the parameter) or MAY proceed without an error(since OAuth 2.0 permits the parameter to be omitted in this case).
            var redirectUris = webServerConfiguration.GetSection("redirect_uris").Get<string[]>();
            var redirectUri = requestBody.FirstOrDefault(c => c.StartsWith(TokenRequest.RedirectUri)).Split("=")[1];
            if (!redirectUris.Contains(redirectUri))
                return StatusCode(400, "redirect_uri is mismatch!");

            // TODO: by default, those two go along together, it may wrong in future coding
            if (loginSession.LoginSession.CodeChallenge != null && loginSession.LoginSession.CodeChallengeMethod != null)
            {
                var codeVerifier = requestBody.FirstOrDefault(c => c.StartsWith(TokenRequest.CodeVerifier)).Split("=")[1];

                var code_challenge = RNGCryptoServicesUltilities.Base64urlencodeNoPadding(codeVerifier.WithSHA265());
                if (!code_challenge.Equals(loginSession.LoginSession.CodeChallenge))
                    return StatusCode(400, "code verifier is wrong!");
            }

            if (loginSession.LoginSession.IsInLoginSession)
            {
                var user = _userDbServices.GetUserWithTokenResponse(loginSession.User.UserName);
                // TODO: get all login session belong to user with a particular client, but not other client
                var latestLoginSession = user.LoginSessionsWithResponse
                    .Where(l => l.LoginSession != null && l.LoginSession.Client.ClientId == clientId && l.TokenResponse != null)
                    .LastOrDefault();
                // TODO: at this step, need to check offline_access is inside authrization login request is true or fault
                //     : if fault, then response will not include refresh token
                //     : if true, then add refresh token along with response

                object responseBody = new object();

                if (latestLoginSession != null)
                {
                    //var tokenResponse = _loginSessionManager.CreateTokenResponse(latestLoginSession);
                    var id_token = GenerateIdToken(user, loginSession.LoginSession.Scope, loginSession.LoginSession.Nonce, client);
                    bool isOfflineAccess = loginSession.LoginSession.IsOfflineAccess;
                    if (isOfflineAccess)
                    {
                        if (latestLoginSession.TokenResponse.RefreshTokenExpiried == null)
                        {
                            if (latestLoginSession.TokenResponse.AccessTokenExpiried >= DateTime.Now)
                            {
                                var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                                string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                                string refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                                tokenResponse.AccessToken = access_token;
                                tokenResponse.IdToken = id_token;
                                tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                                tokenResponse.RefreshToken = refresh_token;
                                tokenResponse.RefreshTokenExpiried = DateTime.Now.AddHours(4);

                                responseBody = new
                                {
                                    access_token = access_token,
                                    id_token = id_token,
                                    refresh_token = refresh_token,
                                    token_type = "Bearer",
                                    // TODO: set by seconds
                                    expires_in = (latestLoginSession.TokenResponse.AccessTokenExpiried - DateTime.Now).Value.TotalSeconds
                                };
                            }
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

                                responseBody = new
                                {
                                    access_token = latestLoginSession.TokenResponse.AccessToken,
                                    id_token = id_token,
                                    refresh_token = refresh_token,
                                    token_type = "Bearer",
                                    // TODO: set by seconds
                                    expires_in = 3600
                                };
                            }
                        }
                        else
                        {
                            if (latestLoginSession.TokenResponse.AccessTokenExpiried >= DateTime.Now
                                && latestLoginSession.TokenResponse.RefreshTokenExpiried >= DateTime.Now)
                            {
                                responseBody = new
                                {
                                    access_token = latestLoginSession.TokenResponse.AccessToken,
                                    id_token = id_token,
                                    refresh_token = latestLoginSession.TokenResponse.RefreshToken,
                                    token_type = "Bearer",
                                    // TODO: set by seconds
                                    expires_in = (latestLoginSession.TokenResponse.AccessTokenExpiried - DateTime.Now).Value.TotalSeconds
                                };
                            }
                            else if (latestLoginSession.TokenResponse.AccessTokenExpiried < DateTime.Now
                                    && latestLoginSession.TokenResponse.RefreshTokenExpiried >= DateTime.Now)
                            {
                                // TODO: has error in this part, but I will fix it later
                                var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                                string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                                tokenResponse.AccessToken = access_token;
                                tokenResponse.IdToken = id_token;
                                tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);

                                if (isOfflineAccess)
                                {
                                    var refresh_token = latestLoginSession.TokenResponse.RefreshToken;
                                    if (string.IsNullOrEmpty(refresh_token))
                                        refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                                    tokenResponse.RefreshToken = refresh_token;
                                    DateTime expiredIn = DateTime.Now;
                                    if (latestLoginSession.TokenResponse.RefreshTokenExpiried != null)
                                    {
                                        TimeSpan diff = (TimeSpan)(latestLoginSession.TokenResponse.RefreshTokenExpiried - DateTime.Now);
                                        double seconds = diff.TotalSeconds;

                                        expiredIn.AddSeconds(seconds);
                                    }

                                    tokenResponse.RefreshTokenExpiried = expiredIn;

                                    responseBody = new
                                    {
                                        access_token = access_token,
                                        id_token = id_token,
                                        refresh_token = refresh_token,
                                        token_type = "Bearer",
                                        // TODO: set by seconds
                                        expires_in = tokenResponse.AccessTokenExpiried
                                    };
                                }
                                else
                                {
                                    responseBody = new
                                    {
                                        access_token = access_token,
                                        id_token = id_token,
                                        token_type = "Bearer",
                                        // TODO: set by seconds
                                        expires_in = tokenResponse.AccessTokenExpiried
                                    };
                                }

                                loginSession.TokenResponse = tokenResponse;
                            }

                            else if (latestLoginSession.TokenResponse.AccessTokenExpiried < DateTime.Now
                                && latestLoginSession.TokenResponse.RefreshTokenExpiried < DateTime.Now)
                            {
                                return StatusCode(401, "re-authenticate!");
                            }
                        }
                    }
                    else
                    {
                        if (loginSession.TokenResponse.AccessTokenExpiried < DateTime.Now)
                            return StatusCode(401, "re-authenticate!");

                        // TODO: need to re-authenticate
                        var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                        string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                        tokenResponse.AccessToken = access_token;
                        tokenResponse.IdToken = id_token;
                        tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                        responseBody = new
                        {
                            access_token = access_token,
                            id_token = id_token,
                            token_type = "Bearer",
                            // TODO: set by seconds
                            expires_in = 3600
                        };

                        loginSession.TokenResponse = tokenResponse;
                    }

                    loginSession.LoginSession.IsInLoginSession = false;
                    _loginSessionManager.UpdateInsideTokenResponse(loginSession);
                    _loginSessionManager.UpdateLoginSessionWithRelation(loginSession);

                    return Ok(JsonConvert.SerializeObject(responseBody));
                }
                else
                //if (loginSession.TokenResponse == null)
                {
                    bool isOfflineAccess = loginSession.LoginSession.IsOfflineAccess;
                    var tokenResponse = _loginSessionManager.CreateTokenResponse(loginSession);
                    var id_token = GenerateIdToken(user, loginSession.LoginSession.Scope, loginSession.LoginSession.Nonce, client);
                    string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                    tokenResponse.AccessToken = access_token;
                    tokenResponse.IdToken = id_token;

                    if (isOfflineAccess)
                    {
                        string refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                        tokenResponse.RefreshToken = refresh_token;
                        tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                        tokenResponse.RefreshTokenExpiried = DateTime.Now.AddHours(4);

                        responseBody = new
                        {
                            access_token = access_token,
                            id_token = id_token,
                            refresh_token = refresh_token,
                            token_type = "Bearer",
                            // TODO: set by seconds
                            expires_in = 3600
                        };
                    }
                    else
                    {
                        responseBody = new
                        {
                            access_token = access_token,
                            id_token = id_token,
                            token_type = "Bearer",
                            // TODO: set by seconds
                            expires_in = 3600
                        };
                    }

                    loginSession.TokenResponse = tokenResponse;

                    loginSession.LoginSession.IsInLoginSession = false;

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

        // TODO: by oauth flow, need access token to be verified before using this function
        //     : done using access token, verify with authorization: bearer
        [HttpGet("userinfo")]
        [Authorize]
        public async Task<ActionResult> GetUserInfo()
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
                email_confirmed = user.EmailConfirmed,
                picture = user.Avatar
            };

            return StatusCode(200, JsonConvert.SerializeObject(responseBody));
        }

        [HttpGet("userinfo.email")]
        // TODO: by oauth flow, need access token to be verified before using this function
        [Authorize]
        public async Task<ActionResult> GetUserInfoAndEmail()
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
        public async Task<ActionResult> AuthorizationPost()
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
        public async Task<ActionResult> ConfirmEmail()
        {
            try
            {
                if (!HttpContext.Request.QueryString.HasValue)
                    return StatusCode(400, "query_string_is_mismatch!");

                var query = HttpContext.Request.Query;
                var userId = int.Parse(query["userId"]);
                var code = query["code"];

                var user = _userDbServices.GetUserWithRelation(userId);
                //var user = _userDbServices.GetUserIncludeConfirmEmail(userId);
                if (!user.ConfirmEmail.ConfirmCode.Equals(code))
                    return StatusCode(404, "Confirm code is not match!");
                if (!(user.ConfirmEmail.ExpiryTime > DateTime.Now))
                    return StatusCode(400, "Confirm code is expired!");
                else
                {
                    user.IsEmailConfirmed = true;
                    user.ConfirmEmail.IsConfirmed = true;
                }

                _userDbServices.SaveChanges();
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

            // TODO: why code is not included in request's header,
            //     : because I like it to be include in query's string!
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

        public async Task<ActionResult> RegisterUser(string state)
        {
            try
            {
                var headers = HttpContext.Request.Headers;
                if (headers.Authorization[0] == null)
                    return StatusCode(400, "Authorization header is missing!");

                var authorization = headers.Authorization[0];
                string email = headers["Email"];
                //var roles = headers["Roles"].ToString().Split(",");
                var userNamePassword = (authorization.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, "").Trim()).ToBase64Decode();

                // TODO: will need to validate username and password, from client and server
                string userName = userNamePassword.Split(":")[0];
                string password = userNamePassword.Split(":")[1];

                if (string.IsNullOrEmpty(password))
                    return StatusCode(400, "password is missing!");

                //var hashPassword = Cast(PasswordUltilities.HashPassword(password), new { Password = "", Salt = "" });
                var currentUser = _userDbServices.GetUserByUserName(userName);
                if (currentUser != null)
                    return StatusCode(409, "user with this username is already exist");

                // TODO: for test, I comment this part
                //if (!string .IsNullOrEmpty(email))
                //{
                //    var emailCheck = _userManager.FindByEmailAsync(email);
                //    if (currentUser != null)
                //        return StatusCode(409, "email can only be used for one account!");
                //}                

                var user = _userDbServices.InitiateUserWithRoles(userName, new string[] { }, email);

                //_userManager.p
                // TODO
                var result = await _userManager.CreateAsync(user, password);
                //var result = _userDbServices.Create(user);
                if (result.Succeeded)
                {

                    //    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");
                    if (!string.IsNullOrEmpty(user.Email))
                        await SendVerifyingEmail(user);

                    object responseBody = new
                    {
                        status = 200,
                        message = "new user is created!"
                    };
                    if (!string.IsNullOrEmpty(state))
                    {
                        responseBody = new
                        {
                            status = 200,
                            message = "new user is created!",
                            state = state
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

        [HttpGet]
        [Authorize]
        public async Task<ActionResult> SendVerifyEmailRequest()
        {
            var userClaims = HttpContext.User;

            var user = await _userManager.GetUserAsync(userClaims);

            // TODO: will check again
            if (user == null)
                return StatusCode(500, "error!");
            if (user.EmailConfirmed == true)
                return StatusCode(400, "user's email is already confirmed!");

            return await SendVerifyingEmail(user);
        }

        private async Task<ActionResult> SendVerifyingEmail(PrMUser user)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //var sr = _userManager.get
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            await CreateConfirmEmail(user, code);

            string callbackUrl = string.Format("{0}?area=Identity&userId={1}&code={2}",
                   $"{Request.Scheme}://{Request.Host}/oauth2/ConfirmEmail",
                   user.Id,
                   code);

            var email = new MimeMessage();
            email.From.Add(new MailboxAddress(_mailSettings.Name, _mailSettings.EmailId));
            // TODO: test email for now
            email.To.Add(new MailboxAddress(user.UserName, user.Email));

            email.Subject = "Testing out email sending";
            email.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                //Text = $"<b>Hello all the way from the land of C# {callbackUrl}</b>"
                Text = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>."
            };

            using (var smtp = new SmtpClient())
            {
                smtp.Connect(_mailSettings.Host, 587, false);

                // Note: only needed if the SMTP server requires authentication
                smtp.Authenticate(_mailSettings.EmailId, _mailSettings.Password);

                smtp.Send(email);
                smtp.Disconnect(true);
            }

            return Ok();
        }

        private async Task CreateConfirmEmail(PrMUser user, string code)
        {
            try
            {
                var nw = _emailDbServices.CreateWithoutSaveChanges();
                nw.ConfirmCode = code;
                nw.User = user;
                nw.IsConfirmed = false;
                nw.ExpiryTime = DateTime.Now.AddHours(1);
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
        private string GenerateIdToken(PrMUser user, string scopeStr, string nonce, PrMClient client)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var scopes = scopeStr.Split(" ");

            var claims = new List<Claim>();

            if (scopes.Contains(IdentityServerConstants.StandardScopes.OpenId))
            {
                claims.Add(new Claim(JwtClaimTypes.Subject, user.UserName));
                claims.Add(new Claim(JwtClaimTypes.Audience, client.ClientId));
                // TODO: hard code for now
                claims.Add(new Claim(JwtClaimTypes.Issuer, System.Uri.EscapeDataString("https://localhost:7180")));
            }
            if (scopes.Contains(IdentityServerConstants.StandardScopes.Profile))
            {
                // TODO: will add more
                claims.Add(new Claim(JwtClaimTypes.Name, user.FullName));
                claims.Add(new Claim("Username", user.UserName));
                claims.Add(new Claim(JwtClaimTypes.Gender, user.Gender));
                claims.Add(new Claim(JwtClaimTypes.UpdatedAt, user.UpdateTime.ToString()));
                claims.Add(new Claim(JwtClaimTypes.Picture, user.Avatar));
                //claims.Add(new Claim(JwtClaimTypes.Locale, user.lo))
            }
            if (scopes.Contains(IdentityServerConstants.StandardScopes.Email))
            {
                claims.Add(new Claim(JwtClaimTypes.Email, user.Email));
                claims.Add(new Claim(JwtClaimTypes.EmailVerified, user.EmailConfirmed.ToString()));
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

        private T Cast<T>(object obj, T model)
        {
            return (T)obj;
        }
    }
}
