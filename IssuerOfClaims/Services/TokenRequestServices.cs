using IssuerOfClaims.Database;
using IssuerOfClaims.Services.Database;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Services
{
    public class TokenRequestServices : ITokenRequestServices
    {
        private ITokenRequestHandlerDbServices _requestHandlerServices;
        //private ITokenResponseDbServices _responseServices;
        //private ITokenRequestSessionDbServices _requestSessionServices;
        private ILogger _logger;

        public TokenRequestServices(ITokenRequestHandlerDbServices requestHandlerServices, ILoggerFactory logger)
            //ITokenResponseDbServices responseServices, ITokenRequestSessionDbServices requestSessionServices,
        {
            //_configuration = configuration;
            //var dbContext = CreateDbContext(configuration);

            _requestHandlerServices = requestHandlerServices;
            //_responseServices = responseServices;
            //_requestSessionServices = requestSessionServices;

            _logger = logger.CreateLogger("TokenRequestServices");
        }

        public TokenRequestHandler CreateTokenRequestSession(PrMUser user, PrMClient client)
        {
            var newObj = new TokenRequestHandler()
            {
                //User = user,
                TokenRequestSession = new TokenRequestSession()
                {
                    //Client = client
                }
            };

            try
            {
                //if (_requestHandlerServices.IsValueCreated)
                _requestHandlerServices.Create(newObj);
            }
            catch (Exception)
            {

                throw;
            }


            return newObj;
        }

        //public TokenRequestHandler FindByAuthorizationCode(string authorizationCode)
        //{
        //    var obj = _requestHandlerServices.FindLoginSessionWithAuthorizationCodeAsync(authorizationCode);

        //    return obj;
        //}

        public bool WhenLoginComplete(TokenRequestHandler session)
        {
            try
            {
                session.TokenRequestSession.IsInLoginSession = false;
                _requestHandlerServices.Update(session);

                //_loginSession.Remove(session);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        public bool UpdateTokenRequestSession(TokenRequestHandler session)
        {
            //if (session.TokenResponse != null)
            //{
            //    _responseServices.Update(session.TokenResponse);
            //}
            //if (session.TokenRequestSession != null)
            //{
            //    _requestSessionServices.Update(session.TokenRequestSession);
            //}
            //_logger.LogInformation(1, $"FindByAccessToken current thread is {Thread.CurrentThread.ManagedThreadId}");

            return _requestHandlerServices.Update(session);
        }

        //public TokenResponse CreateTokenResponse(TokenRequestHandler session)
        //{
        //    var obj = new TokenResponse()
        //    {
        //        TokenRequestHandler = session,
        //    };

        //    _responseServices.Create(obj);
        //    //_loginServices.SaveChanges();

        //    return obj;
        //}

        //public bool UpdateInsideTokenResponse(TokenRequestHandler session)
        //{
        //    if (session.TokenResponse != null)
        //    {
        //        _responseServices.Update(session.TokenResponse);
        //        return true;
        //    }
        //    return false;
        //}

        public TokenRequestHandler FindByAccessToken(string accessToken)
        {
            var session = _requestHandlerServices.FindByAccessToken(accessToken);

            return session;
        }

        public TokenRequestHandler FindByRefreshToken(string refreshToken)
        {
            var session = _requestHandlerServices.FindByRefreshToken(refreshToken);

            return session;
        }

        // TODO:
        // Create new session's object whenever a request involve with identity services is called
        // - set for it authorization code when authorization code flow is initiated, add code challenger, add id token, access token expired time and access token when a request for access token include grant_type is called
        // - set for it id token and access token when implicit grant (with form_post or not) is initiated
        // =>  after everything is done following a particular flow which is used for authentication, save this session object to database
        // - TODO: these following few lines is good ideal, I think, but I have problems when trying to implement it, so for now, I save everything in db
        // * Note: I don't want to save it when initiate authentication process and get it from database when it's call,
        //       : because, a particular session is used along with authentication process will be the latest, and search for it in db can create performance cost when this server is used long enough.
        //       : instead of search from db, save 100 session in used, and get it from memory (from authorization code, or id_token) is easier than query 100 object from 100.000 object table...

        private DbContextManager CreateDbContext(IConfigurationManager configuration)
        {
            var contextOptions = new DbContextOptionsBuilder<DbContextManager>()
                 .UseSqlServer(configuration.GetConnectionString(DbUltilities.DatabaseName))
                 .Options;

            var dbContext = new DbContextManager(contextOptions, null);
            return dbContext;
        }
    }

    public interface ITokenRequestServices
    {
        //TokenResponse CreateTokenResponse(TokenRequestHandler loginSession);
        TokenRequestHandler CreateTokenRequestSession(PrMUser user, PrMClient client);
        //TokenRequestHandler FindByAuthorizationCode(string authorizationCode);
        TokenRequestHandler FindByAccessToken(string accessToken);
        TokenRequestHandler FindByRefreshToken(string refreshToken);
        bool UpdateTokenRequestSession(TokenRequestHandler session);
        //bool UpdateInsideTokenResponse(TokenRequestHandler session);
        bool WhenLoginComplete(TokenRequestHandler session);
    }
}
