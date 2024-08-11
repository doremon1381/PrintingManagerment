using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PrintingManagermentServer.Controllers.Ultility;
using PrMServerUltilities.Identity;
using System.Collections;
using System.Net;
using System.Security.Claims;

namespace PrintingManagermentServer.Controllers
{
    [ApiController]
    [AllowAnonymous]
    [Route("[controller]")]
    //[ApiVersion("1.0")]
    [ControllerName("auth")]
    //[Authorize]
    public class IdentityRequestController : ControllerBase
    {
        private readonly IConfigurationManager _configuration;

        public IdentityRequestController(IConfigurationManager configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("google")]
        public async Task<ActionResult> GoogleAuthenticating()
        {
            // send accesstoken to identityserver and get jwt token or id token
            var serverClientConfiguration = _configuration.GetSection(IdentityServerConfiguration.IDENTITYSERVER);

            var clientId = serverClientConfiguration[IdentityServerConfiguration.CLIENT_ID];
            // create claimprincipal, save to httpcontext

            // return jwt token as id token from identity server

            return new StatusCodeResult(200);
        }

        [HttpGet("callback")]
        public ActionResult Callback()
        {
            return StatusCode(200);
        }

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

            return StatusCode(200, "form_post is sent to server successfull!");
        }


        [HttpGet("basicAccess")]
        [Authorize]
        public ActionResult ImplementImplicitGrantFlow()
        {
            // TODO: will update this method
            var headers = HttpContext.Request.Headers;
            // TOOD: will update this conditional check
            if (headers.WWWAuthenticate[0] != null && headers.WWWAuthenticate[0].StartsWith(IdentityServerConfiguration.SCHEME_BASIC))
            {
                var authenticate = HttpContext.Request.Headers.WWWAuthenticate[0];
                var userNamePassword = Base64Decode(authenticate.Replace(IdentityServerConfiguration.SCHEME_BASIC, "").Trim());

                string userName = userNamePassword.Split(":")[0];
                string password = userNamePassword.Split(":")[1];

                //// TODO: Do authentication of userId and password against your credentials store here
                //var user = _userDbServices.GetByUserNameWithRelation(userName);

                //if (user != null)
                //{
                //    var salt = user.PasswordHashSalt;

                //    //var salt = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(5);
                //    var passwordHash = string.Format("{0}{1}", password, salt).GetStringWithSHA256();
                //    var isPasswordMatched = passwordHash.Equals(user.PasswordHash);
                //}
                //else
                //{
                //    return StatusCode(404, "User is not found!");
                //}

                //if (true)
                //{
                //    var claims = new List<Claim>
                //    {
                //        new Claim(ClaimTypes.Name, userName),
                //        new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Password)
                //    };

                //    var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.SCHEME_BASIC) });
                //    Thread.CurrentPrincipal = principal;
                //    if (HttpContext != null)
                //    {
                //        HttpContext.User = principal;
                //        //var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                //        //code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                //        //var callbackUrl = Url.Page(
                //        //   "/Account/ConfirmEmail",
                //        //   pageHandler: null,
                //        //   values: new { area = "Identity", userId = user.Id, code = code },
                //        //protocol: Request.Scheme);

                //        //await _emailSender.SendEmailAsync(Input.Email, "Confirm your email",
                //        //    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                //    }

                //    var idToken = GenerateToken(user);

                //    // TODO: will need to validate this token of client's side 

                //    return StatusCode(200, idToken);
                //}

            }

            return StatusCode(302, "Will send id_token or something!");

            //return StatusCode(200);
        }

        [HttpPost("registerUser")]
        public async Task<ActionResult> RegisterNewUser()
        {
            var identityServerConfiguration = _configuration.GetSection(IdentityServerConfiguration.IDENTITYSERVER);

            string registerUri = identityServerConfiguration[IdentityServerConfiguration.REGISTER_ENDPOINT];
            string authorizationHeader = HttpContext.Request.Headers["Register"];

            // sends the request
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(registerUri);
            tokenRequest.Method = "POST";
            tokenRequest.Headers.Add(string.Format("Register: {0}", authorizationHeader));
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            try
            {
                // gets the response
                WebResponse tokenResponse = await tokenRequest.GetResponseAsync();

                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    // reads response body
                    string responseText = await reader.ReadToEndAsync();
                    //output(responseText);

                    //// converts to dictionary
                    //Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                    //string access_token = tokenEndpointDecoded["access_token"];
                    //userinfoCall(access_token);

                    //id_token = tokenEndpointDecoded["id_token"];
                }
            }
            catch (WebException ex)
            {

            }

            return StatusCode(201, "User is created!");
        }

        private string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }
    }
}
