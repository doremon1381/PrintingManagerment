using IssuerOfClaims.Database;
using PrMDbModels;

namespace IssuerOfClaims.Services
{
    public class PrMLoginSessionManager : IPrMLoginSessionManager
    {
        // TODO: save current is 
        //private static List<LoginSessionWithResponse> _loginSession;
        private ITokenRequestHandlerDbServices _loginServices;
        private ITokenResponseDbServices _tokenResponseServices;
        private ITokenRequestSessionDbServices _loginSessionServices;

        static PrMLoginSessionManager()
        {
            //_loginSession = new List<LoginSessionWithResponse>();
        }

        public PrMLoginSessionManager(ITokenRequestHandlerDbServices loginServices, ITokenResponseDbServices tokenResponseServices, ITokenRequestSessionDbServices requiredLoginSessionDbServices)
        {
            _loginServices = loginServices;
            _tokenResponseServices = tokenResponseServices;
            _loginSessionServices = requiredLoginSessionDbServices;
        }

        public TokenRequestHandler CreateUserLoginSession(PrMUser user, PrMClient client)
        {
            var newObj = new TokenRequestHandler()
            {
                User = user,
                TokenRequestSession = new TokenRequestSession()
                {
                    Client = client
                }
            };

            _loginServices.Create(newObj);

            return newObj;
        }

        public TokenRequestHandler FindByAuthorizationCode(string authorizationCode)
        {
            var obj = _loginServices.FindLoginSessionWithAuthorizationCode(authorizationCode);

            return obj;
        }

        public bool WhenLoginComplete(TokenRequestHandler session)
        {
            try
            {
                session.TokenRequestSession.IsInLoginSession = false;
                _loginServices.Update(session);

                //_loginSession.Remove(session);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        public bool UpdateLoginSessionWithRelation(TokenRequestHandler session)
        {
            if (session.TokenResponse != null)
            {
                _tokenResponseServices.Update(session.TokenResponse);
            }
            if (session.TokenRequestSession != null)
            {
                _loginSessionServices.Update(session.TokenRequestSession);
            }

            return _loginServices.Update(session);
        }

        public TokenResponse CreateTokenResponse(TokenRequestHandler session)
        {
            var obj = new TokenResponse()
            {
                TokenRequestHandler = session,
            };

            _tokenResponseServices.Create(obj);
            //_loginServices.SaveChanges();

            return obj;
        }

        public bool UpdateInsideTokenResponse(TokenRequestHandler session)
        {
            if (session.TokenResponse != null)
            {
                _tokenResponseServices.Update(session.TokenResponse);
                return true;
            }
            return false;
        }

        public TokenRequestHandler FindByAccessToken(string accessToken)
        {
            var session = _loginServices.FindByAccessToken(accessToken);

            return session;
        }

        public TokenRequestHandler FindByRefreshToken(string refreshToken)
        {
            var session = _loginServices.FindByRefreshToken(refreshToken);

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


    }

    public interface IPrMLoginSessionManager
    {
        TokenResponse CreateTokenResponse(TokenRequestHandler loginSession);
        TokenRequestHandler CreateUserLoginSession(PrMUser user, PrMClient client);
        TokenRequestHandler FindByAuthorizationCode(string authorizationCode);
        TokenRequestHandler FindByAccessToken(string accessToken);
        TokenRequestHandler FindByRefreshToken(string refreshToken);
        bool UpdateLoginSessionWithRelation(TokenRequestHandler session);
        bool UpdateInsideTokenResponse(TokenRequestHandler session);
        bool WhenLoginComplete(TokenRequestHandler session);
    }
}
