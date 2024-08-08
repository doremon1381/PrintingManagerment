using Azure.Core;
using Duende.IdentityServer.Models;
using IssuerOfClaims.Controllers.Ultility;
using IssuerOfClaims.Database;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;
using PrMDbModels;
using System.Net;
using System.Security.Claims;
using System.Text;
using static IdentityModel.OidcConstants;

namespace IssuerOfClaims.Controllers
{
    [ApiController]
    [AllowAnonymous]
    [Route("[controller]")]
    //[ApiVersion("1.0")]
    [ControllerName("oauth2")]
    public class IdentityRequestController : ControllerBase
    {
        //private readonly ILogger<IdentityRequestController> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfigurationManager _configurationManager;
        private readonly IPrMUserDbServices _prMUserDbServices;

        private const string SCHEME = "Basic";

        public IdentityRequestController(ILogger<IdentityRequestController> logger, IPrMUserDbServices userDbServices)
        {
            //_logger = logger;
            //_httpClientFactory = httpClientFactory;
            //_configurationManager = configuration;
            _prMUserDbServices = userDbServices;
        }

        /// <summary>
        /// authorization_endpoint
        /// </summary>
        /// <returns></returns>
        [HttpGet("auth")]
        public async Task<ActionResult> Authorization()
        {
            // 1. Get authorization request from server
            // 2. Return an http 302 message to server, give it a nonce cookie (for now, ignore this part),
            //    if asking for google, then send a redirect to google to get authorization code
            //    if basic access, then return a redirect to another request to identity server - send request to "authentication/basicAccess" route
            // 3.

            return StatusCode(200);
        }

        [HttpGet("token")]
        public async Task<ActionResult> TokenEnpoint()
        {
            return StatusCode(200);
        }

        //[HttpPost("v{version:apiVersion}/authentication/google")]
        [HttpGet("authentication/google")]
        public async Task<ActionResult> GoogleAuthenticating()
        {
            string clientID = "";
            string clientSecret = "";
            string authorizationEndpoint = "https://accounts.google.com/o/oauth2/auth";
            string tokenEndpoint = "https://oauth2.googleapis.com/token";
            string userInfoEndpoint = "https://www.googleapis.com/oauth2/userinfo";

            var requestHeaders = HttpContext.Request.Headers;
            var authenticationRequestBody = new
            {
                AuthorizationCode = requestHeaders["code"],
                RedirectUri = System.Uri.EscapeDataString("http://127.0.0.1:59867/"),
                ClientId = clientID,
                CodeVerifier = requestHeaders["code_verifier"],
                ClientSecret = clientSecret
            };


            // builds the  request
            string tokenRequestURI = "https://www.googleapis.com/oauth2/v4/token";
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code",
                authenticationRequestBody.AuthorizationCode,
                System.Uri.EscapeDataString("http://127.0.0.1:59867/"),
                clientID,
                authenticationRequestBody.CodeVerifier,
                clientSecret
                //authenticationRequestBody.ClientId,
                //authenticationRequestBody.ClientSecret
                );

            //string tokenRequestURI = $"https://localhost:7180/oauth2/authentication/google";
            //string tokenRequestBody = string.Format("code={0}&code_verifier={1}",
            //    code,
            //    code_verifier
            ////clientSecret
            //);

            // sends the request
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenRequestURI);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            string id_token = "";
            try
            {
                // gets the response
                WebResponse tokenResponse = await tokenRequest.GetResponseAsync();

                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    // reads response body
                    string responseText = await reader.ReadToEndAsync();
                    //output(responseText);

                    // converts to dictionary
                    Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                    string access_token = tokenEndpointDecoded["access_token"];
                    //userinfoCall(access_token);

                    id_token = tokenEndpointDecoded["id_token"];
                }
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

            return Ok(id_token);
        }

        async void userinfoCall(string access_token)
        {
            //output("Making API Call to Userinfo...");

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
            }
        }

        //[HttpPost("v{version:apiVersion}/authentication/basicAccess")]
        [HttpGet("authentication/basicAccess")]
        public ActionResult LoginWithUserNameAndPassword()
        {
            // TODO: will update this method
            var headers = HttpContext.Request.Headers;
            if (headers.Authorization[0] != null && SCHEME.Equals(headers.Authorization[0].StartsWith("Basic")))
            {
                var authorization = HttpContext.Request.Headers.Authorization[0];
                var userNamePassword = Base64Decode(authorization.Replace("Basic", "").Trim());

                string userName = userNamePassword.Split(":")[0];
                string password = userNamePassword.Split(":")[1];

                // TODO: Do authentication of userId and password against your credentials store here
                var user = _prMUserDbServices.GetByUserName(userName);
                
                if (user != null)
                {
                    var salt = user.PasswordHashSalt;

                    //var salt = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(5);
                    var passwordHash = string.Format("{0}{1}", password, salt).GetStringWithSHA256();

                }
                else
                {
                    return StatusCode(404, "User is not found!");
                }

                if (true)
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, userName),
                        new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Password)
                    };

                    var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, SCHEME) });
                    Thread.CurrentPrincipal = principal;
                    if (HttpContext != null)
                        HttpContext.User = principal;
                }

            }

            return StatusCode(302, "Will send id_token or something!");
        }

        [HttpGet("authentication/register")]
        public async Task<ActionResult> RegisterUser()
        {
            var headers = HttpContext.Request.Headers;
            if (headers.Authorization[0] != null && SCHEME.Equals(headers.Authorization[0].Split(" ")[0]))
            {
                var authorization = HttpContext.Request.Headers.Authorization[0];
                var userNamePassword = Base64Decode(authorization.Replace("Basic", "").Trim());

                string userName = userNamePassword.Split(":")[0];
                string password = userNamePassword.Split(":")[1];

                var salt = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(5);
                var passwordHash = string.Format("{0}{1}", password, salt).GetStringWithSHA256();

                var user = new PrMUser()
                {
                    UserName = userName,
                    Password = passwordHash,
                    PasswordHashSalt = salt,

                };

                _prMUserDbServices.CreateNewUser(user);
            }
            return StatusCode(200, "New User is created!");
        }

        private string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }
    }
}
