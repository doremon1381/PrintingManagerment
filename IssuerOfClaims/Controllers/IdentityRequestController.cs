﻿using IssuerOfClaims.Controllers.Ultility;
using ServerUltilities.Extensions;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using MimeKit;
using Newtonsoft.Json;
using ServerDbModels;
using ServerUltilities;
using ServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Extensions;
using IssuerOfClaims.Services.Token;
using static ServerUltilities.Identity.OidcConstants;
using IssuerOfClaims.Services;

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

        private readonly IApplicationUserManager _applicationUserManager;
        private readonly IConfigurationManager _configuration;
        private readonly IConfirmEmailDbServices _emailDbServices;
        private readonly MailSettings _mailSettings;
        private readonly ITokenManager _tokenManager;
        private readonly IClientDbServices _clientDbServices;

        public IdentityRequestController(ILogger<IdentityRequestController> logger, IConfigurationManager configuration
            , IApplicationUserManager userManager
            , ITokenManager tokenManager
            , IConfirmEmailDbServices emailDbServices, MailSettings mailSettings, IClientDbServices clientDbServices)
        {
            _logger = logger;
            _configuration = configuration;

            _applicationUserManager = userManager;
            _emailDbServices = emailDbServices;
            _mailSettings = mailSettings;
            _clientDbServices = clientDbServices;

            _tokenManager = tokenManager;
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
            try
            {
                // 1. Get authorization request from server
                // 2. Return an http 302 message to server, give it a nonce cookie (for now, ignore this part),
                //    if asking for google, then send a redirect to google to get authorization code
                //    if basic access (I mean implicit grant - form_post or not), then return a redirect to another request to identity server - send request to "authentication/basicAccess" route
                // 3.

                Oauth2Parameters parameters = new Oauth2Parameters(HttpContext.Request.QueryString.Value);

                var client = _clientDbServices.GetByClientId(parameters.ClientId.Value);
                if (client == null
                    || client.Id == 0)
                    return StatusCode(400, "client id is wrong!");

                string[] redirectUris = client.RedirectUris.Split(",");
                if (!redirectUris.Contains(parameters.RedirectUri.Value))
                    return StatusCode(400, "redirectUri is mismatch!");

                if (parameters.Scope.Value.Contains(IdentityServerConstants.StandardScopes.OpenId))
                    switch (parameters.ResponseType.Value)
                    {
                        case ResponseTypes.Code:
                            return await IssueAuthorizationCodeAsync(parameters);
                        //break;
                        case ResponseTypes.IdToken:
                            return await ImplicitGrantWithFormPostAsync(parameters);
                        //break;
                        // TODO: will implement another flow if I have time
                        default:
                            break;
                    }
                else
                {
                    // TODO: if in scope doesnot have openid, it still valid in some case but it's not an Authentication Request that use Oauth2 as standard
                    return StatusCode(500, "Not yet know why...");
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return StatusCode(500, "Not yet know why...");
        }


        #region Issue authorization code
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
        private async Task<ActionResult> IssueAuthorizationCodeAsync(Oauth2Parameters parameters)
        {
            // TODO: comment for now
            //     : by using AuthenticateHanlder, in this step, authenticated is done
            //     : get user, create authorization code, save it to login session and out

            UserIdentity user = await ACF_I_GetResourceOwnerIdentity();
            var client = _clientDbServices.GetByClientId(parameters.ClientId.Value);

            ACF_I_VerifyClient(parameters.Scope.Value, client);

            var acfProcessSession = _tokenManager.CreateTokenRequestSession();
            ACF_I_UpdateRequestSessionDetails(parameters, acfProcessSession, client, out string authorizationCode);
            ACF_I_CreateTokenRequestHandler(user, acfProcessSession);

            // TODO: using this function because has an error with tracking object, for now i dont know why 
            var requestSession = _tokenManager.FindRequestSessionById(acfProcessSession.Id);
            requestSession.Client = client;
            _tokenManager.UpdateTokenRequestSession(requestSession);

            // Create a custom response object
            object responseBody = new
            {
                state = parameters.State.Value,
                code = authorizationCode
            };

            ACF_I_AddResponseStatus(200);

            return StatusCode(200, System.Text.Json.JsonSerializer.Serialize(responseBody));
        }

        private async Task<UserIdentity> ACF_I_GetResourceOwnerIdentity()
        {
            var obj = await _applicationUserManager.Current.GetUserAsync(HttpContext.User);

            if (obj == null)
                throw new InvalidDataException(ExceptionMessage.USER_NULL);

            return obj;
        }

        private void ACF_I_AddResponseStatus(int statusCode)
        {
            // TODO: change for now
            HttpContext.Response.StatusCode = statusCode;
            // TODO: has error
            //HttpContext.Response.Headers.Append("state", state);

            // TODO: I don't know why if add "Location" as key in response header, the response will be sent to vuejs's web is with status code 200,
            //     : but if I modify the name, for example, to "Location1", then the response will has status code 302 as I set to it before...
            //HttpContext.Response.Headers.Append("location", string.Format("{0}?code={1}", redirectUri, authorizationCode));
        }

        private void ACF_I_VerifyClient(string scopes, Client client)
        {
            if (client.Id == 0)
                throw new InvalidDataException(ExceptionMessage.INVALID_CLIENTID);
            if (!ACF_I_IsSimilarWithClientScopes(scopes, client))
                throw new InvalidDataException(ExceptionMessage.SCOPES_NOT_ALLOWED);
        }
        private bool ACF_I_IsSimilarWithClientScopes(string scopes, Client client)
        {
            var variables = System.Uri.UnescapeDataString(scopes).Split(" ");
            foreach (var s in variables)
            {
                if (!client.AllowedScopes.Contains(s))
                    return false;
            }
            return true;
        }
        /// <summary>
        /// TODO: will fix some error when adding transient or scopped dbcontext
        /// </summary>
        /// <param name="user"></param>
        /// <param name="ACFProcessSession"></param>
        private TokenRequestHandler ACF_I_CreateTokenRequestHandler(UserIdentity user, TokenRequestSession ACFProcessSession)
        {
            var tokenRequestHandler = _tokenManager.GetDraftTokenRequestHandler();
            tokenRequestHandler.User = user;
            tokenRequestHandler.TokenRequestSession = ACFProcessSession;

            // TODO: will check again
            _tokenManager.UpdateTokenRequestHandler(tokenRequestHandler);

            return tokenRequestHandler;
        }
        private void ACF_I_UpdateRequestSessionDetails(Oauth2Parameters parameters, TokenRequestSession ACFProcessSession, Client client, out string authorizationCode)
        {
            ACF_I_ImportPKCERequestedParams(parameters.CodeChallenge.Value, parameters.CodeChallengeMethod.Value, parameters.CodeChallenge.HasValue, ACFProcessSession);
            ACF_I_ImportRequestSessionData(parameters.Scope.Value, parameters.Nonce.Value, client, ACFProcessSession, out authorizationCode);
        }
        private void ACF_I_ImportRequestSessionData(string scope, string nonce, Client client, TokenRequestSession tokenRequestSession, out string authorizationCode)
        {
            // TODO: create authorization code
            authorizationCode = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(32);

            tokenRequestSession.AuthorizationCode = authorizationCode;
            tokenRequestSession.Nonce = nonce;
            tokenRequestSession.Scope = scope;
            tokenRequestSession.IsOfflineAccess = scope.Contains(StandardScopes.OfflineAccess);
            _tokenManager.UpdateTokenRequestSession(tokenRequestSession);
        }
        private void ACF_I_ImportPKCERequestedParams(string codeChallenge, string codeChallengeMethod, bool codeChallenge_HasValue, TokenRequestSession tokenRequestSession)
        {
            if (codeChallenge_HasValue)
            {
                tokenRequestSession.CodeChallenge = codeChallenge;
                tokenRequestSession.CodeChallengeMethod = codeChallengeMethod;
            }
        }
        #endregion

        #region resiger user
        // TODO: by default, I seperate the need of creating identity of someone with the flow of oauth2's authorization code flow 
        //     : but following specs, my implement maybe wrong, but I know it is optional or "more guideline" than "actual rules"
        [HttpPost("register")]
        //[Authorize]
        public async Task<ActionResult> RegisterIdentity()
        {
            try
            {
                RegisterParameters parameters = new RegisterParameters(RequestQueryToStringArray(), HttpContext.Request.Headers);

                ValidateRedirectUri(parameters);

                return await RegisterUserAsync(parameters);
            }
            catch (Exception ex)
            {
                // TODO: will check again
                _logger.LogError($"REGISTER ENDPOINT: {ex.Message}");
                throw;
            }
        }

        private Client GetClient(string clientId)
        {
            var client = _clientDbServices.GetByClientId(clientId);
            if (client == null || client.Id == 0)
                throw new InvalidDataException("client id is wrong!");

            return client;
        }

        private void ValidateRedirectUri(RegisterParameters parameters)
        {
            Client client = GetClient(parameters.ClientId.Value);

            string[] redirectUris = client.RedirectUris.Split(",");
            if (!redirectUris.Contains(parameters.RedirectUri.Value))
                throw new InvalidDataException("redirectUri is mismatch!");
        }

        private string[] RequestQueryToStringArray()
        {
            if (string.IsNullOrEmpty(HttpContext.Request.QueryString.Value))
                throw new InvalidDataException(ExceptionMessage.QUERYSTRING_NOT_NULL_OR_EMPTY);

            return HttpContext.Request.QueryString.Value.Remove(0, 1).Split("&");
        }

        public async Task<ActionResult> RegisterUserAsync(RegisterParameters parameters)
        {
            // TODO: will add role later

            var currentUser = _applicationUserManager.Current.Users.ToList().Find(u => u.UserName == parameters.UserName.Value);
            if (currentUser != null)
                return StatusCode(409, "user with this username is already exist");

            var newUser = new UserIdentity
            {
                UserName = parameters.UserName.Value,
                Email = parameters.Email.Value,
                FirstName = parameters.FirstName.Value,
                LastName = parameters.LastName.Value,
                FullName = string.Format("{0} {1}", parameters.LastName.Value, parameters.FirstName.Value),
                Gender = parameters.Gender.Value
            };

            // TODO: will check again
            var result = _applicationUserManager.Current.CreateAsync(newUser, parameters.Password.Value).Result;

            if (result.Succeeded)
            {
                var user = _applicationUserManager.Current.Users.ToList()
                    .Find(u => u.UserName == parameters.UserName.Value);
                // TODO: https://openid.net/specs/openid-connect-prompt-create-1_0.html#name-authorization-request
                var client = _clientDbServices.GetByClientId(parameters.ClientId.Value);

                string id_token = _tokenManager.GenerateIdToken(newUser, string.Empty, parameters.Nonce.Value, client.ClientId);
                user.IdToken = new IdToken()
                {
                    Token = id_token,
                    CreateTime = user.UpdateTime
                };

                result = _applicationUserManager.Current.UpdateAsync(user).Result;

                if (parameters.Email.HasValue)
                    await SendVerifyingEmailAsync(newUser, "ConfirmEmail", client);

                object responseBody = CreateRegisterUserResponseBody(id_token, parameters.State.Value, parameters.State.HasValue);

                return StatusCode(200, responseBody);
            }
            else
            {
                return StatusCode(500, "Internal server error!");
            }
        }

        private static object CreateRegisterUserResponseBody(string id_token, string state = "", bool stateHasValue = false)
        {
            object responseBody = new
            {
                status = 200,
                message = "new user is created!",
                id_token = id_token
            };

            if (stateHasValue)
            {
                responseBody = new
                {
                    status = 200,
                    message = "new user is created!",
                    state = state,
                    id_token = id_token
                };
            }

            return responseBody;
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
        private async Task<ActionResult> ImplicitGrantWithFormPostAsync(Oauth2Parameters parameters)
        {
            try
            {
                // TODO: for this situation, Thread and http context may not need
                //var principal = Thread.CurrentPrincipal;
                var principal = HttpContext.User;

                var user = await _applicationUserManager.Current.GetUserAsync(principal);
                var client = _clientDbServices.GetByClientId(parameters.ClientId.Value);

                // TODO: scope is used for getting claims to send to client,
                //     : for example, if scope is missing email, then in id_token which will be sent to client will not contain email's information 
                var idToken = _tokenManager.GenerateIdToken(user, parameters.Scope.Value, parameters.Nonce.Value, client.ClientId);

                //var tokenResponse = _tokenManager.GenerateIdToken();

                // TODO: update must follow order, I will explain late
                //IGF_UpdateTokenResponse(idToken, tokenResponse);
                IGF_UpdateTokenRequestHandler(user, client, idToken);

                // Check response mode to know what kind of response is going to be used
                // return a form_post, url fragment or body of response
                if (parameters.ResponseMode.Value.Equals(ResponseModes.FormPost))
                {
                    Dictionary<string, string> inputBody = new Dictionary<string, string>();
                    inputBody.Add(AuthorizeResponse.IdentityToken, idToken);

                    //string formPost = GetFormPostHtml(webServerConfiguration["redirect_uris:0"], inputBody);
                    string formPost = GetFormPostHtml(parameters.RedirectUri.Value, inputBody);

                    HttpContext.Response.Headers.Append("state", parameters.State.Value);

                    // TODO: will learn how to use this function
                    await WriteHtmlAsync(HttpContext.Response, formPost);

                    // TODO: will learn how to use it later
                    return new EmptyResult();
                }
                else if (parameters.ResponseMode.Value.Equals(ResponseModes.Fragment))
                {
                    // TODO:
                }
                else if (parameters.ResponseMode.Value.Equals(ResponseModes.Query))
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

        private void IGF_UpdateTokenRequestHandler(UserIdentity user, Client client, string idToken)
        {
            //var tokenRequestHandler = _tokenRequestHandlerDbServices.GetDraftObject();
            //var tokenRequestSession = IGF_CreateRequestSession(client);

            //tokenRequestHandler.User = user;
            //tokenRequestHandler.TokenRequestSession = tokenRequestSession;

            //// TODO: need to add id token to this part

            //_tokenRequestHandlerDbServices.Update(tokenRequestHandler);
        }

        private void IGF_UpdateTokenResponse(string idToken, ServerDbModels.TokenResponse tokenResponse)
        {
            // TODO
            //tokenResponse.IdToken = idToken;

            //_tokenResponseDbServices.Update(tokenResponse);
        }

        //private TokenRequestSession IGF_CreateRequestSession(Client client)
        //{
        //    var tokenRequestSession = _tokenRequestSessionDbServices.CreateTokenRequestSession();

        //    tokenRequestSession.Client = client;
        //    tokenRequestSession.Scope = client.AllowedScopes;
        //    tokenRequestSession.IsInLoginSession = false;
        //    tokenRequestSession.IsOfflineAccess = false;

        //    _tokenRequestSessionDbServices.Update(tokenRequestSession);

        //    return tokenRequestSession;
        //}

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

        #region Issue token
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
            try
            {
                // TODO: for now, only response to authorization code request to access token
                //     : need to implement another action
                //     : send back access_token when have request refresh 

                Dictionary<string, string> requestBody = await TokenResponse_GetRequestBodyAsync();

                // TODO: will fix it later
                string grantType = requestBody[TokenRequest.GrantType];

                switch (grantType)
                {
                    case OidcConstants.GrantTypes.RefreshToken:
                        {
                            // 1. check token response information.
                            // 2. check request for that response, which it has offline access or not
                            // 3. check expired time of refresh token and access token
                            // 4. issue new access token if there is no problem
                            // TODO: return new accesstoken using refresh token if it's not expired
                            //var loginSessionWithToken = _tokenRequestManager.FindByRefreshToken(grantType);

                            return StatusCode(500, "not implement exception!");
                        }
                    case OidcConstants.GrantTypes.AuthorizationCode:
                        return await IssueAccessTokenForAuthorizationCodeAsync(requestBody);
                    default:
                        return StatusCode(500, "Unknown error!");
                }
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        private async Task<Dictionary<string, string>> TokenResponse_GetRequestBodyAsync()
        {
            var requestBody = new Dictionary<string, string>();
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
                throw new InvalidDataException(ExceptionMessage.REQUEST_BODY_NOT_NULL_OR_EMPTY);

            return requestBody;
        }

        private async Task<ActionResult> IssueAccessTokenForAuthorizationCodeAsync(Dictionary<string, string> requestBody)
        {
            // TODO: get from queryString, authorization code
            //     : get user along with authorization code inside latest login session (of that user)
            //     : create access token and id token, send it to client

            string authCode = ACF_II_VerifyAndGetAuthCodeFromRequest(requestBody);

            //// TODO: hotfix for now
            //var _tokenRequestHandlerDbServices = _servicesProvider.GetService<ITokenRequestHandlerDbServices>();

            // TODO: for now, every request, by default in scop will have openid, so ignore this part of checking now
            //     : Verify that the Authorization Code used was issued in response to an OpenID Connect Authentication Request(so that an ID Token will be returned from the Token Endpoint).
            var tokenRequestHandler = _tokenManager.FindTokenRequestHandlerByAuthorizationCode(authCode);

            var client = ACF_II_VerifyAndGetClient(requestBody, tokenRequestHandler);

            ACF_II_VerifyRequestParameters(requestBody, tokenRequestHandler, client);

            // TODO: will change to use email when allow using identity from another source
            UserIdentity user = ACF_II_GetResourceOwnerIdentity(tokenRequestHandler.User.UserName);

            // TODO: issue token from TokenManager
            var tokenResponses = _tokenManager.IssueToken(user, client, tokenRequestHandler.Id);

            return StatusCode(200, System.Text.Json.JsonSerializer.Serialize(tokenResponses));
        }

        private UserIdentity ACF_II_GetResourceOwnerIdentity(string userName)
        {
            var obj = _applicationUserManager.UserIdentities
                    //.Include(u => u.TokenRequestHandlers)
                    //.Include(u => u.TokenRequestHandlers).ThenInclude(l => l.TokenRequestSession).ThenInclude(s => s.Client).ToList()
                    .FirstOrDefault(u => u.UserName == userName);
            if (obj == null)
                throw new InvalidDataException(ExceptionMessage.USER_NULL);

            return obj;
        }

        private void ACF_II_VerifyRequestParameters(Dictionary<string, string> requestBody, TokenRequestHandler tokenRequestHandler, Client client)
        {
            ACF_II_VerifyRedirectUris(requestBody, client);
            ACF_II_VerifyCodeChallenger(requestBody, tokenRequestHandler);
        }

        private void ACF_II_VerifyRedirectUris(Dictionary<string, string> requestBody, Client client)
        {
            //Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that was included in the initial Authorization Request.
            //If the redirect_uri parameter value is not present when there is only one registered redirect_uri value,
            //the Authorization Server MAY return an error(since the Client should have included the parameter) or MAY proceed without an error(since OAuth 2.0 permits the parameter to be omitted in this case).
            string[] redirectUris = client.RedirectUris.Split(",");
            var redirectUri = requestBody[TokenRequest.RedirectUri];
            if (!redirectUris.Contains(redirectUri))
                throw new InvalidOperationException("redirect_uri is mismatch!");
        }

        private string ACF_II_VerifyAndGetAuthCodeFromRequest(Dictionary<string, string> requestBody)
        {
            string authorizationCode = requestBody[TokenRequest.Code];

            if (string.IsNullOrEmpty(authorizationCode))
                throw new NullReferenceException("authorization code is missing!");

            return authorizationCode;
        }

        private void ACF_II_VerifyCodeChallenger(Dictionary<string, string> requestBody, TokenRequestHandler tokenRequestHandler)
        {
            // TODO: by default, those two go along together, it may wrong in future coding
            if (tokenRequestHandler.TokenRequestSession.CodeChallenge != null
                && tokenRequestHandler.TokenRequestSession.CodeChallengeMethod != null)
            {
                var codeVerifier = requestBody[TokenRequest.CodeVerifier];
                if (string.IsNullOrEmpty(codeVerifier))
                    throw new NullReferenceException("code challenge is included in authorization code request but does not have in access token request!");

                var code_challenge = RNGCryptoServicesUltilities.Base64urlencodeNoPadding(codeVerifier.WithSHA265());
                if (!code_challenge.Equals(tokenRequestHandler.TokenRequestSession.CodeChallenge))
                    throw new InvalidOperationException("code verifier is wrong!");
            }
        }

        private Client ACF_II_VerifyAndGetClient(Dictionary<string, string> requestBody, TokenRequestHandler tokenRequestHandler)
        {
            string clientId = requestBody[TokenRequest.ClientId];
            string clientSecret = requestBody[TokenRequest.ClientSecret];

            var client = new Client();
            if (string.IsNullOrEmpty(clientId)
                || string.IsNullOrEmpty(clientSecret))
                throw new NullReferenceException("client credentials's info is missing!");

            //// TODO: hotfix for now
            //var _clientDbServices = _servicesProvider.GetService<IClientDbServices>();
            client = _clientDbServices.GetByIdAndSecret(clientId, clientSecret);
            if (tokenRequestHandler.TokenRequestSession != null
                && !tokenRequestHandler.TokenRequestSession.Client.Id.Equals(client.Id))
                // TODO: status code may wrong
                throw new InvalidOperationException("something wrong with client which Authorization Code was issued to!");

            return client;
        }

        [HttpGet("userinfo")]
        [Authorize]
        public async Task<ActionResult> GetUserInfoAsync()
        {
            // TODO: exchange access token to get user from latest login session inside memory
            //     : create user_info json response to send to client

            // TODO: by using authorization before this part, so it should has an user in HttpContext
            //     : in current context of services, when I use async, this function return an error about "connection is lost"...
            var user = _applicationUserManager.Current.GetUserAsync(HttpContext.User).Result;

            if (user == null)
                throw new InvalidOperationException(ExceptionMessage.USER_NULL);

            object responseBody = ResponseForUserInfoRequest(user);

            return StatusCode(200, JsonConvert.SerializeObject(responseBody));
        }

        private static object ResponseForUserInfoRequest(UserIdentity user)
        {
            return new
            {
                sub = user.UserName,
                name = user.FullName,
                email = user.Email,
                email_confirmed = user.IsEmailConfirmed,
                picture = user.Avatar
            };
        }

        [HttpGet("userinfo.email")]
        [Authorize]
        public async Task<ActionResult> GetUserInfoAndEmailAsync()
        {
            // TODO: exchange access token to get user from latest login session inside memory
            //     : create user_info json response to send to client

            return StatusCode(200);
        }
        #endregion

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
                var user = _applicationUserManager.Current.Users.Include(u => u.ConfirmEmails).FirstOrDefault(u => u.Id == userId);
                var createUserConfirmEmail = user.ConfirmEmails.FirstOrDefault(e => e.Purpose == (int)ConfirmEmailPurpose.CreateIdentity);

                //var user = _userDbServices.GetUserIncludeConfirmEmail(userId);
                if (!createUserConfirmEmail.ConfirmCode.Equals(code))
                    return StatusCode(404, "Confirm code is not match!");
                if (!(createUserConfirmEmail.ExpiryTime > DateTime.Now))
                    return StatusCode(400, "Confirm code is expired!");
                if (createUserConfirmEmail.IsConfirmed == true)
                    return StatusCode(200, "Email is confirmed!");
                else
                {
                    user.IsEmailConfirmed = true;
                    createUserConfirmEmail.IsConfirmed = true;
                }

                var temp = _applicationUserManager.Current.UpdateAsync(user).Result;
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
            string authorizationCode = queryString.GetFromQueryString("code");
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
        // TODO: will update later
        public async Task<ActionResult> UpdateUserAsync()
        {
            var userClaims = HttpContext.User;

            var user = await _applicationUserManager.Current.GetUserAsync(userClaims);

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
            string clientId = queryBody.GetFromQueryString(JwtClaimTypes.ClientId);
            if (string.IsNullOrEmpty(clientId))
                return StatusCode(400, "client id is missing!");

            var emailForChangingPassword = _emailDbServices.GetByCode(code);
            if (!emailForChangingPassword.Purpose.Equals((int)ConfirmEmailPurpose.ChangePassword))
                return StatusCode(500, "something inside this process is wrong!");
            if (!emailForChangingPassword.ExpiryTime.HasValue || emailForChangingPassword.ExpiryTime < DateTime.Now)
                return StatusCode(500, "error with email's expired time!");

            var user = emailForChangingPassword.User;
            try
            {
                _applicationUserManager.Current.RemovePasswordAsync(user);
                _applicationUserManager.Current.AddPasswordAsync(user, password);
                emailForChangingPassword.IsConfirmed = true;
                _emailDbServices.Update(emailForChangingPassword);
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

                string clientId = queryBody.GetFromQueryString(JwtClaimTypes.ClientId);
                if (string.IsNullOrEmpty(clientId))
                    return StatusCode(400, "client id is missing!");
                string email = queryBody.GetFromQueryString(JwtClaimTypes.Email);
                if (string.IsNullOrEmpty(email))
                    return StatusCode(400, "email is missing!");

                var client = _clientDbServices.GetByClientId(clientId);
                if (client == null)
                    return StatusCode(404, "client id may wrong!");

                // TODO: get user by email, by logic, username + email is unique for an user that is stored in db, but fow now, email may be duplicated for test
                var user = _applicationUserManager.Current.Users.FirstOrDefault(u => u.Email.Equals(email));
                await SendForgotPasswordCodeToEmail(user, client);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
            return Ok();
        }

        private async Task<ActionResult> SendForgotPasswordCodeToEmail(UserIdentity user, Client client)
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

        private async Task SendVerifyingEmailAsync(UserIdentity user, string callbackEndpoint, Client client)
        {
            var code = await _applicationUserManager.Current.GenerateEmailConfirmationTokenAsync(user);
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
        }

        private bool SendEmail(UserIdentity user, string emailBody)
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

        private async Task CreateConfirmEmailAsync(UserIdentity user, string code, Client client, ConfirmEmailPurpose purpose, int expiredTimeInMinutes)
        {
            try
            {
                var nw = _emailDbServices.GetDraft();
                nw.ConfirmCode = code;
                nw.Purpose = (int)purpose;
                nw.IsConfirmed = false;
                nw.ExpiryTime = DateTime.Now.AddMinutes(expiredTimeInMinutes);
                nw.CreatedTime = DateTime.Now;

                if (_emailDbServices.Create(nw))
                {
                    nw.User = user;
                    nw.Client = client;

                    _emailDbServices.Update(nw);
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
        private string GenerateAccessToken(UserIdentity user)
        {
            return string.Empty;
        }

        private T Cast<T>(object obj, T model)
        {
            return (T)obj;
        }
    }
}
