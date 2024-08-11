using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using IdentityModel;
using IssuerOfClaims.Controllers.Ultility;
using IssuerOfClaims.Database;
using IssuerOfClaims.Models;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using Newtonsoft.Json;
using PrMDbModels;
using PrMServerUltilities;
using PrMServerUltilities.Identity;
using System.Collections.Specialized;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
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
        private readonly ILogger<IdentityRequestController> _logger;
        //private readonly IHttpClientFactory _httpClientFactory;
        private readonly IPrMUserDbServices _userDbServices;

        private readonly IPrMRoleDbServices _roleDbServices;

        private readonly SignInManager<PrMUser> _signInManager;
        private readonly UserManager<PrMUser> _userManager;
        private readonly IConfigurationManager _configuration;
        private readonly IConfirmEmailDbServices _emailDbServices;
        //private readonly MailSettings _mailSettings;

        #region from https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/Crypto.cs
        private const int PBKDF2IterCount = 1000; // default for Rfc2898DeriveBytes
        private const int PBKDF2SubkeyLength = 256 / 8; // 256 bits
        private const int SaltSize = 128 / 8; // 128 bits
        #endregion

        public IdentityRequestController(ILogger<IdentityRequestController> logger, IPrMUserDbServices userDbServices
            , IConfigurationManager configuration, IPrMRoleDbServices roleDbServices, SignInManager<PrMUser> signInManager, UserManager<PrMUser> userManager
            , IConfirmEmailDbServices emailDbServices)
        //, IPrMRoleDbServices roleDbServices, IPrMPermissionDbServices permissionDbServices, SignInManager<PrMUser> signInManager, UserManager<PrMUser> userManager)
        {
            _logger = logger;
            _configuration = configuration;
            //_httpClientFactory = httpClientFactory;
            _userDbServices = userDbServices;
            //_roles = prMRoles;
            _roleDbServices = roleDbServices;
            _signInManager = signInManager;
            _userManager = userManager;
            _emailDbServices = emailDbServices;
            //_mailSettings = mailSettings;
            //_permissionDbServices = permissionDbServices;
        }

        /// <summary>
        /// authorization_endpoint
        /// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        /// <returns></returns>
        [HttpGet("authorize")]
        public async Task<ActionResult> Authorization()
        {
            // 1. Get authorization request from server
            // 2. Return an http 302 message to server, give it a nonce cookie (for now, ignore this part),
            //    if asking for google, then send a redirect to google to get authorization code
            //    if basic access, then return a redirect to another request to identity server - send request to "authentication/basicAccess" route
            // 3.
            if (!HttpContext.Request.QueryString.HasValue)
                return StatusCode(400, "Request must containt query string for authorization!");

            var queryString = HttpContext.Request.QueryString.Value.Remove(0, 1).Split("&");
            var responseType = queryString.First(q => q.StartsWith(AuthorizeRequest.ResponseType));

            // check response type
            if (ParamOfRequestNullableCheck(responseType, AuthorizeRequest.ResponseType))
                return StatusCode(400, "Response type is null!");

            responseType = responseType.Replace(AuthorizeRequest.ResponseType + "=", "");
            // check response mode
            string responseMode = queryString.First(q => q.StartsWith(AuthorizeRequest.ResponseMode));

            // TODO: by default when response mode is not set for response type is , use 
            if (ParamOfRequestNullableCheck(responseMode, AuthorizeRequest.ResponseMode))
                responseMode = GetDefaultResponseModeByResponseType(responseType);
            else
                responseMode = responseMode.Replace(AuthorizeRequest.ResponseMode + "=", "");

            // TODO: try to add nonce in flow, will check it late
            var nonce = queryString.First(q => q.StartsWith(AuthorizeRequest.Nonce));
            var webServerConfiguration = _configuration.GetSection(IdentityServerConfiguration.WEB_SERVER);
            var headers = HttpContext.Request.Headers;

            switch (responseType)
            {
                case OidcConstants.ResponseTypes.Code:
                    AuthorizationCodeFlow();
                    break;
                case OidcConstants.ResponseTypes.IdToken:
                    #region Implicit grant (with form_post) flow

                    if (string.IsNullOrEmpty(nonce))
                        return StatusCode(400, "By using implicit grant flow, nonce must be set by client!");

                    // TOOD: will update this conditional check
                    if (headers.WWWAuthenticate[0] != null && headers.WWWAuthenticate[0].StartsWith(IdentityServerConfiguration.SCHEME_BASIC))
                    {
                        var authenticate = HttpContext.Request.Headers.WWWAuthenticate[0];
                        var userNamePassword = Base64Decode(authenticate.Replace(IdentityServerConfiguration.SCHEME_BASIC, "").Trim());

                        string userName = userNamePassword.Split(":")[0];
                        string password = userNamePassword.Split(":")[1];

                        // TODO: Do authentication of userId and password against your credentials store here
                        var user = _userDbServices.GetByUserNameWithRelation(userName);

                        if (user != null)
                        {
                            //var salt = user.PasswordHashSalt;

                            ////var salt = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(5);
                            //var passwordHash = string.Format("{0}{1}", password, salt).GetStringWithSHA256();
                            //var isPasswordMatched = passwordHash.Equals(user.PasswordHash);

                            try
                            {
                                // TOOD: comment for now, because _signInManager.PasswordSignInAsync has error response
                                //var result = await _signInManager.PasswordSignInAsync(user.UserName,
                                //password, true, lockoutOnFailure: true);
                                //if (result.Succeeded)
                                //{
                                // TODO: use for now, currently not decide how the authentication will be done
                                //     : use jwt token or cookie, I want to use jwt, but that's for tomorrow
                                var claims = new List<Claim>
                                    {
                                        new Claim(ClaimTypes.Name, userName),
                                        new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Password)
                                    };

                                var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.SCHEME_BASIC) });

                                Thread.CurrentPrincipal = principal;
                                if (HttpContext != null)
                                {
                                    HttpContext.User = principal;
                                    //HttpContext.Response.Cookies
                                }

                                var idToken = GenerateToken(user, nonce.Replace(JwtRegisteredClaimNames.Nonce + "=", ""));

                                // Check response mode to know what kind of response is going to be used
                                // return a form_post, url fragment or body of response
                                if (responseMode.Equals(OidcConstants.ResponseModes.FormPost))
                                {
                                    var state = queryString.First(q => q.StartsWith(AuthorizeRequest.State));
                                    if (ParamOfRequestNullableCheck(state, AuthorizeRequest.State))
                                        return StatusCode(400, "State of request must be implemented!");

                                    Dictionary<string, string> inputBody = new Dictionary<string, string>();
                                    inputBody.Add(AuthorizeResponse.IdentityToken, idToken);
                                    inputBody.Add(AuthorizeResponse.State, state.Replace(AuthorizeRequest.State + "=", ""));

                                    string formPost = GetFormPostHtml(webServerConfiguration["redirect_uris:0"], inputBody);

                                    // TODO: will learn how to use this function
                                    // await HttpContext.Response.WriteHtmlAsync(formPost);

                                    // TODO: will need to validate this token of client's side 
                                    return StatusCode(200, formPost);
                                }
                                else if (responseMode.Equals(OidcConstants.ResponseModes.Fragment))
                                {

                                }
                                else if (responseMode.Equals(OidcConstants.ResponseModes.Query))
                                {
                                    // TODO: will need to add state into response, return this form for now
                                    return StatusCode(200, idToken);
                                }
                                else
                                {
                                    return StatusCode(400, "Response mode is not allowed!");
                                }
                                //}
                                //if (result.RequiresTwoFactor)
                                //{
                                //    //return RedirectToPage("./LoginWith2fa", new
                                //    //{
                                //    //    ReturnUrl = returnUrl,
                                //    //    RememberMe = Input.RememberMe
                                //    //});
                                //}
                                //if (result.IsLockedOut)
                                //{
                                //    //_logger.LogWarning("User account locked out.");
                                //    //return RedirectToPage("./Lockout");
                                //}
                                //else
                                //{
                                //    //ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                                //    //return Page();
                                //}
                            }
                            catch (Exception ex)
                            {
                                return StatusCode(500, ex.Message);
                            }
                        }
                        else
                            return StatusCode(404, "User is not found!");
                    }
                    #endregion
                    break;
                // TODO: will implement another flow if I have time
                default:
                    break;
            }

            return StatusCode(200);
        }

        /// <summary>
        /// it's struct inside request is {requestParam.Name}={requestParam.Value}
        /// </summary>
        /// <param name="requestParam"></param>
        /// <returns></returns>
        private bool ParamOfRequestNullableCheck(string requestParam, string nameOfParam)
        {
            if (string.IsNullOrEmpty(requestParam)
                || string.IsNullOrEmpty(requestParam.Replace(nameOfParam + "=", "")))
                return true;

            // TODO: will add new condition
            return false;
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

        private ActionResult AuthorizationCodeFlow()
        {


            return StatusCode(200);
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

        [HttpGet("token")]
        public async Task<ActionResult> TokenEnpoint()
        {
            return StatusCode(200);
        }

        [HttpGet("ConfirmEmail")]
        public ActionResult ConfirmEmail()
        {
            try
            {
                var query = HttpContext.Request.Query;
                var userId = int.Parse(query["userId"]);
                var code = query["code"];

                var user = _userDbServices.GetUserIncludeConfirmEmail(userId);
                if (!user.ConfirmEmail.ConfirmCode.Equals(code))
                    return StatusCode(404, "Confirm code is not match!");
                if (!(user.ConfirmEmail.ExpiryTime >= DateTime.Now))
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

        //[HttpPost("v{version:apiVersion}/authentication/google")]
        [HttpGet("authentication/google")]
        public async Task<ActionResult> GoogleAuthenticating()
        {
            var googleClientConfiguration = _configuration.GetSection(IdentityServerConfiguration.GOOGLE_CLIENT);

            string clientID = googleClientConfiguration[IdentityServerConfiguration.CLIENT_ID];
            string clientSecret = googleClientConfiguration[IdentityServerConfiguration.CLIENT_SECRET];
            string authorizationEndpoint = googleClientConfiguration[IdentityServerConfiguration.AUTHORIZATION_ENDPOINT];
            string tokenEndpoint = googleClientConfiguration[IdentityServerConfiguration.TOKEN_ENDPOINT];
            string[] redirectUris = googleClientConfiguration.GetSection(IdentityServerConfiguration.REDIRECT_URIS).Get<string[]>();
            //string projectId = googleClientConfiguration[IdentityServerConfiguration.PROJECT_ID];
            //string userInfoEndpoint = "https://www.googleapis.com/oauth2/userinfo";

            var requestHeaders = HttpContext.Request.Headers;
            var authenticationRequestBody = new
            {
                AuthorizationCode = requestHeaders["code"],
                RedirectUri = System.Uri.EscapeDataString(redirectUris[1]),
                ClientId = clientID,
                CodeVerifier = requestHeaders["code_verifier"],
                ClientSecret = clientSecret
            };


            // builds the  request
            //string tokenRequestURI = tokenEndpoint;
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code",
                authenticationRequestBody.AuthorizationCode,
                System.Uri.EscapeDataString(redirectUris[1]),
                clientID,
                authenticationRequestBody.CodeVerifier,
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
                    id_token = tokenEndpointDecoded["id_token"];
                    id_token = userinfoCall(access_token).Result;
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

        //[HttpPost("v{version:apiVersion}/authentication/basicAccess")]
        [HttpGet("basicAccess")]
        public async Task<ActionResult> LoginWithUserNameAndPasswordAsync()
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

                // TODO: Do authentication of userId and password against your credentials store here
                var user = _userDbServices.GetByUserNameWithRelation(userName);

                if (user != null)
                {
                    var salt = user.PasswordHashSalt;

                    //var salt = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(5);
                    var passwordHash = string.Format("{0}{1}", password, salt).GetStringWithSHA256();
                    var isPasswordMatched = passwordHash.Equals(user.PasswordHash);
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

                    var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.SCHEME_BASIC) });
                    Thread.CurrentPrincipal = principal;
                    if (HttpContext != null)
                    {
                        HttpContext.User = principal;
                        //var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        //code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                        //var callbackUrl = Url.Page(
                        //   "/Account/ConfirmEmail",
                        //   pageHandler: null,
                        //   values: new { area = "Identity", userId = user.Id, code = code },
                        //protocol: Request.Scheme);

                        //await _emailSender.SendEmailAsync(Input.Email, "Confirm your email",
                        //    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                    }

                    var idToken = GenerateToken(user, "");

                    // TODO: will need to validate this token of client's side 

                    return StatusCode(200, idToken);
                }

            }

            return StatusCode(302, "Will send id_token or something!");
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

        // To generate token
        private string GenerateToken(PrMUser user, string nonce)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new List<Claim>();

            if (string.IsNullOrEmpty(nonce))
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, user.UserName));
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, user.UserName));
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
            }

            user.PrMPermissions.ForEach(p =>
            {
                claims.Add(new Claim(ClaimTypes.Role, p.Role.RoleName));
            });

            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
                _configuration["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);


            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        [HttpPost("register")]
        public async Task<ActionResult> RegisterUser()
        {
            try
            {
                var headers = HttpContext.Request.Headers;
                if (headers["Register"][0] != null)
                {
                    var authorization = headers["Register"][0];
                    var email = headers["Email"];
                    var roles = headers["Roles"].ToString().Split(",");
                    var userNamePassword = Base64Decode(authorization.Trim());

                    // TODO: will need to check username and password, from client and server
                    string userName = userNamePassword.Split(":")[0];
                    string password = userNamePassword.Split(":")[1];

                    if (password == null)
                        throw new ArgumentNullException("password");

                    //var salt = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(5);
                    //var passwordHash = string.Format("{0}{1}", password, salt).GetStringWithSHA256();
                    var hashPassword = Cast(HashPassword(password), new { Password = "", Salt = "" });
                    //var s = VerifyHashedPassword(hashPassword.Password, password);
                    var currentUser = _userDbServices.GetUserByUserName(userName);
                    if (currentUser != null)
                        return StatusCode(409, "user with this username is already exist");

                    var user = new PrMUser()
                    {
                        UserName = userName,
                        PasswordHash = hashPassword.Password,
                        PasswordHashSalt = Base64Encode(hashPassword.Salt),
                        Email = email
                    };
                    user.PrMPermissions = roles.Select(roleName => new PrMPermission()
                    {
                        Role = _roleDbServices.GetRoleByName(roleName),
                        User = user
                    }).ToList();

                    //var result = await _userManager.CreateAsync(user, password);
                    var result = _userDbServices.Create(user);
                    if (result)
                    {
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, userName),
                            new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Password)
                        };

                        var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.SCHEME_BASIC) });

                        Thread.CurrentPrincipal = principal;
                        if (HttpContext != null)
                        {
                            HttpContext.User = principal;
                            //HttpContext.Response.Cookies
                        }

                        if (!string.IsNullOrEmpty(user.Email))
                            await SendVerifyingEmail(user);

                        //await _emailSender.SendEmailAsync(Input.Email, "Confirm your email",
                        //    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                        return StatusCode(200, "New User is created!");
                    }
                    else
                    {
                        return StatusCode(500, "Internal server error!");
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Internal server error!");
            }
            return StatusCode(500, "Unknown error!");
        }

        private async Task SendVerifyingEmail(PrMUser user)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            await CreateConfirmEmail(user, code);

            //var callbackUrl = Url.Page(
            //   "/oauth2/ConfirmEmail",
            //   pageHandler: null,
            //   values: new { area = "Identity", userId = user.Id, code = code },
            //protocol: Request.Scheme);
            string callbackUrl = string.Format("{0}?area=Identity&userId={1}&code={2}",
                   $"{Request.Scheme}://{Request.Host}/oauth2/ConfirmEmail",
                   user.Id,
                   code);

            var _mailSettings = _configuration.GetSection("MailSettings");

            var email = new MimeMessage();
            email.From.Add(new MailboxAddress("Doraemon The Blue", _mailSettings["EmailId"]));
            // TODO: test email for now
            email.To.Add(new MailboxAddress(user.UserName, "doremon1380@gmail.com"));

            email.Subject = "Testing out email sending";
            email.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                //Text = $"<b>Hello all the way from the land of C# {callbackUrl}</b>"
                Text = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>."
            };

            using (var smtp = new SmtpClient())
            {
                smtp.Connect(_mailSettings["Host"], 587, false);

                // Note: only needed if the SMTP server requires authentication
                smtp.Authenticate(_mailSettings["EmailId"], _mailSettings["Password"]);

                smtp.Send(email);
                smtp.Disconnect(true);
            }
        }

        private async Task CreateConfirmEmail(PrMUser user, string code)
        {
            try
            {
                var nw = _emailDbServices.CreateWithoutSaveChanges();
                nw.ConfirmCode = code;
                nw.User = user;
                nw.IsConfirmed = false;
                nw.ExpiryTime = DateTime.Now.AddMinutes(2);
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
        /// from https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/Crypto.cs
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public object HashPassword(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            // Produce a version 0 (see comment above) text hash.
            byte[] salt;
            byte[] subkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, SaltSize, PBKDF2IterCount))
            {
                salt = deriveBytes.Salt;
                subkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }

            var outputBytes = new byte[1 + SaltSize + PBKDF2SubkeyLength];
            Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, PBKDF2SubkeyLength);
            return new { Password = Convert.ToBase64String(outputBytes), Salt = System.Text.Encoding.Default.GetString(salt) };
        }

        /// <summary>
        /// from https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/Crypto.cs
        /// hashedPassword must be of the format of HashWithPassword (salt + Hash(salt+input)
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool VerifyHashedPassword(string hashedPassword, string password)
        {
            if (hashedPassword == null)
            {
                return false;
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            var hashedPasswordBytes = Convert.FromBase64String(hashedPassword);

            // Verify a version 0 (see comment above) text hash.

            if (hashedPasswordBytes.Length != (1 + SaltSize + PBKDF2SubkeyLength) || hashedPasswordBytes[0] != 0x00)
            {
                // Wrong length or version header.
                return false;
            }

            var salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPasswordBytes, 1, salt, 0, SaltSize);
            var storedSubkey = new byte[PBKDF2SubkeyLength];
            Buffer.BlockCopy(hashedPasswordBytes, 1 + SaltSize, storedSubkey, 0, PBKDF2SubkeyLength);

            byte[] generatedSubkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, PBKDF2IterCount))
            {
                generatedSubkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            return ByteArraysEqual(storedSubkey, generatedSubkey);
        }

        /// <summary>
        /// from https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/Crypto.cs
        /// Compares two byte arrays for equality. The method is specifically written so that the loop is not optimized.
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        //[MethodImpl(MethodImplOptions.NoOptimization)]
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }

            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }

        private T Cast<T>(object obj, T model)
        {
            return (T)obj;
        }

        public static string Base64Encode(string plainText)
        {
            //byte[] temp_backToBytes = Convert.FromBase64String(temp_inBase64);
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        private string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }
    }
}
