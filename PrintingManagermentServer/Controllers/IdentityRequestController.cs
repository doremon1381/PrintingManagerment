﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PrintingManagermentServer.Controllers.Ultility;
using PrMServerUltilities;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using PrMServerUltilities.Extensions;
using static PrMServerUltilities.Identity.OidcConstants;
using Microsoft.IdentityModel.Tokens;
using PrMModels;
using PrintingManagermentServer.Services;
using Newtonsoft.Json;
using Azure.Core;
using Newtonsoft.Json.Linq;
using PrintingManagermentServer.Models;

namespace PrintingManagermentServer.Controllers
{
    [ApiController]
    [AllowAnonymous]
    [Route("[controller]")]
    //[ApiVersion("1.0")]
    [ControllerName("auth")]
    //[EnableCors("MyPolicy")]
    public class IdentityRequestController : ControllerBase
    {
        private readonly IConfigurationManager _configuration;
        private readonly ILoginSessionManager _loginSessionManager;
        private readonly IUserTokenDbServices _userTokenServices;

        public IdentityRequestController(IConfigurationManager configuration, ILoginSessionManager loginSessionManager, IUserTokenDbServices userTokenDbServices)
        {
            _configuration = configuration;
            _loginSessionManager = loginSessionManager;
            _userTokenServices = userTokenDbServices;
        }

        [HttpGet("callback")]
        public async Task<ActionResult> Callback()
        {
            try
            {
                // TODO: get authorization code inside callback
                var context = HttpContext.Request;
                var queryString = context.QueryString.Value.Remove(0, 1).Split('&');

                // TODO: get state from user-agent, will do it late

                // TODO: get identityserver token endpoint
                var identityConfig = _configuration.GetSection("IdentityServer");
                string? clientId, clientSecret, redirectUri, tokenEndpoint, userInfoEnpoint;

                ConfigurationValidate(identityConfig, out clientId, out clientSecret, out redirectUri, out tokenEndpoint, out userInfoEnpoint);

                var currentState = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(32);

                // TODO: at this step, get a draft of login session in session manager, which has client_state as same as incoming client_state from user-agent
                queryString.GetFromQueryString(TokenRequest.Code, out string code);
                queryString.GetFromQueryString("client_state", out string clientState);

                var loginDraft = _loginSessionManager.GetDraftFromState(clientState);
                string codeVerifier = loginDraft.LoginSession.CodeVerifier;

                string tokenEndpointBody = string.Format("code={0}&client_id={1}&client_secret={2}&audience={3}&grant_type=authorization_code&redirect_uri={4}&code_verifier={5}&state={6}&scope="
                    , code, clientId, clientSecret, "http://localhost:7209", redirectUri, codeVerifier, currentState);

                // TODO: send to identityserver to get id token and access token
                HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenEndpoint);
                tokenRequest.Method = "POST";
                tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenEndpointBody);
                tokenRequest.ContentLength = _byteVersion.Length;
                Stream stream = tokenRequest.GetRequestStream();
                await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
                stream.Close();

                // TODO:  exchange for user_info
                //     : check in web db user token by user name or email
                //     : if do not have one, create one for new user_info
                //     : save loginSession draft - save session that was success

                string responseText = "";

                WebResponse serverResponse = await tokenRequest.GetResponseAsync();
                using (StreamReader reader = new StreamReader(serverResponse.GetResponseStream()))
                {
                    // reads response body
                    responseText = await reader.ReadToEndAsync();
                }

                dynamic sr = JObject.Parse(responseText);

                string accessToken = sr.access_token;
                string id_token = sr.id_token;
                string refresh_token = sr.refresh_token;
                string expired_in = sr.expires_in;

                loginDraft.TokenResponse = new Models.TokenResponse()
                {
                    AccessToken = accessToken,
                    IdToken = id_token,
                    RefreshToken = refresh_token,
                    AccessTokenExpiried = DateTime.Now.AddSeconds(double.Parse(expired_in))
                };

                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadJwtToken(id_token);
                clientId = identityConfig.GetSection("client_id").Value;

                if (jsonToken == null)
                    return StatusCode(404, "token is wrong");
                if (jsonToken.Claims.FirstOrDefault(c => c.Type.Equals("aud") && c.Value.Equals(clientId)) == null)
                {
                    return StatusCode(404, "aud is not valid");
                }
                // TODO: The current time MUST be before the time represented by the exp Claim., dunno how
                if (jsonToken.Claims.FirstOrDefault(c => c.Type.Equals("exp")) != null)
                {
                    //var sr1 = DateTime.Now.;
                    //var sr2 = DateTime.Parse(jsonToken.Claims.FirstOrDefault(c => c.Type.Equals("exp")).Value);
                }
                if (jsonToken.Claims.FirstOrDefault(c => c.Type.Equals("nonce")) != null)
                {
                    var nonce = jsonToken.Claims.FirstOrDefault(c => c.Type.Equals("nonce")).Value;

                    if (!nonce.Equals(loginDraft.LoginSession.Nonce))
                        return StatusCode(404, "nonce is mismatch!");
                }
                jsonToken.Payload.Remove("nonce");


                _loginSessionManager.SaveDraft(loginDraft);
                return StatusCode(200, jsonToken.Payload);

                // TODO: get user info and save to db
                //var user_info = await userinfoCall(accessToken, userInfoEnpoint);

                //var user = _userTokenServices.Create(new UserToken()
                //{
                //    //UserName =
                //});

                //var loginWithToken = new LoginSessionWithToken()
                //{
                //    //UserToken = User
                //};
                //var tokenResponse = new PrintingManagermentServer.Models.TokenResponse()
                //{
                //    AccessToken = accessToken,
                //    IdToken = id_token,
                //    RefreshToken = refresh_token,
                //    AccessTokenExpiried = DateTime.Parse(expired_in)
                //};

            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }

            // TODO: send access token and id token to client, prepare for request have access token in authorization: bearer header

            return StatusCode(200);
        }

        public T Cast<T>(T obj, object test)
        {
            return (T)test;
        }

        private Exception ConfigurationValidate(IConfigurationSection identityConfig, out string? clientId, out string? clientSecret, out string redirectUri, out string? tokenEndpoint, out string? userInfoEnpoint)
        {
            var registerUri = identityConfig.GetSection("auth_uri").Value;
            clientId = identityConfig.GetSection("client_id").Value;
            clientSecret = identityConfig.GetSection("client_secret").Value;
            redirectUri = identityConfig.GetSection("redirect_uris").Get<string[]>().First();
            tokenEndpoint = identityConfig.GetSection("token_uri").Value;
            userInfoEnpoint = identityConfig.GetSection("userinfo_uri").Value;

            if (string.IsNullOrEmpty(registerUri))
                return new Exception("server's config does not have register uri!");
            if (string.IsNullOrEmpty(clientId))
                return new Exception("server's config does not have client_id!");
            if (string.IsNullOrEmpty(clientSecret))
                return new Exception("server's config does not have client_secret!");
            if (string.IsNullOrEmpty(redirectUri))
                return new Exception("redirect_uri is missing!");
            if (string.IsNullOrEmpty(tokenEndpoint))
                return new Exception("tokenEnpoint is missing!");
            if (string.IsNullOrEmpty(userInfoEnpoint))
                return new Exception("userInfoEnpoint is missing!");

            return null;
        }

        private async Task<string> userinfoCall(string access_token, string userInfoUri)
        {
            string output = "";
            // builds the  request

            // sends the request
            HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userInfoUri);
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

        /// <summary>
        /// TODO: callback uses for receiving id_token from identityserver and handle login base on that id_token, nothing more
        /// </summary>
        /// <returns></returns>
        [HttpPost("callback")]
        public ActionResult CallbackPost()
        {
            var request = HttpContext.Request;

            var getForm = request.ReadFormAsync().Result;
            //using (var sr = new StreamReader(Request.InputStream))
            //{
            //    string body = sr.ReadToEnd();

            //    // Deserialize JSON to C# object
            //    // you can use some modern libs such as Newtonsoft JSON.NET instead as well
            //    JavaScriptSerializer serializer = new JavaScriptSerializer();
            //    Hashtable hashtable = serializer.Deserialize<Hashtable>(body);

            //    string name = hashtable["name"].ToString();
            //    string image = hashtable["image"].ToString();
            //    string price = hashtable["price"].ToString();

            //}

            // TODO: get authorization code, exchange it to server


            //return StatusCode(200, "form_post is sent to client successfull!");
            return StatusCode(200, "login success!");
        }

        [HttpPost("authorize")]
        public async Task<ActionResult> Authorization()
        {
            // TODO: get authorization code

            return StatusCode(200);
        }

        [HttpGet("register")]
        [Authorize]
        public async Task<ActionResult> Register()
        {
            var identityConfig = _configuration.GetSection("IdentityServer");
            var registerUri = identityConfig.GetSection("auth_uri").Value;
            if (string.IsNullOrEmpty(registerUri))
                return StatusCode(500, "server's config does not have register uri!");
            var clientId = identityConfig.GetSection("client_id").Value;
            if (string.IsNullOrEmpty(clientId))
                return StatusCode(500, "server's config does not have client_id!");
            //var clientSecret = identityConfig.GetSection("client_secret").Value;
            //if (string.IsNullOrEmpty(clientSecret))
            //    return StatusCode(500, "server's config does not have client_secret!");
            var redirectUri = identityConfig.GetSection("redirect_uris").Get<string[]>().First();
            if (string.IsNullOrEmpty(redirectUri))
                return StatusCode(500, "redirect_uri is missing!");

            string responseUri = string.Format("{0}?response_type=code&client_id={1}&redirect_uri={2}&scope=openid%20profile%20email&prompt=create", registerUri, clientId, System.Uri.EscapeDataString(redirectUri));

            return StatusCode(200, responseUri);
        }

        /// <summary>
        /// TODO: validate at_hash from id_token is OPTIONAL in some flow,
        ///     : I will check when to implement it later, now, better it has than it doesn't
        ///     https://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
        ///     and https://stackoverflow.com/questions/30356460/how-do-i-validate-an-access-token-using-the-at-hash-claim-of-an-id-token
        /// </summary>
        /// <param name="id_token"></param>
        /// <param name="access_token"></param>
        private static void ValidateAtHash(string id_token, string access_token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(id_token);
            var alg = jwtSecurityToken.Header["alg"];
            var at_hash = jwtSecurityToken.Claims.FirstOrDefault(c => c.Type.Equals("at_hash"));
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

                        var access_token_validated = at_hash.Value.Equals(checkPoint);
                    }
                }
            }
        }

        private void GenerateJwtAcessToken(UserToken user, string nonce)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt_access_token:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // TODO: jwt access token's form
            //   Header:
            //       { "typ":"at+JWT","alg":"RS256","kid":"RjEwOwOA"}
            //   Claims:
            //       {
            //           "iss": "my identity server (https://localhost:7180)",
            //"sub": "username",
            //"aud":   "Request url: tinhte.vn or kind of that",
            //"exp": 1639528912,
            //"iat": 1618354090,
            //"jti" : "dbe39bf3a3ba4238a513f51d6e1691c4",
            //"client_id": "s6BhdRkqt3",
            //"scope": "openid profile reademail"
            //      }
            // TODO: by default flow, in this step, I already register a client as claimsPrincipal of identityserver, so

            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));


            if (!string.IsNullOrEmpty(nonce))
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));

            //user.PrMPermissions.ForEach(p =>
            //{
            //    claims.Add(new Claim(ClaimTypes.Role, p.Role.RoleName));
            //});

            // TODO: audience will need to compare with request's header 
            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
                _configuration["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddHours(8),
                signingCredentials: credentials);


            // return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
