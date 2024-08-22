using IssuerOfClaims.Database;
using PrMDbModels;

namespace IssuerOfClaims.Services
{
    public class PrMLoginSessionManager : IPrMLoginSessionManager
    {
        // TODO: save current is 
        //private static List<LoginSessionWithResponse> _loginSession;
        private ILoginSessionWithResponseDbServices _loginServices;
        private ITokenResponseDbServices _tokenResponseServices;
        private IPrMRequiredLoginSessionDbServices _loginSessionServices;

        static PrMLoginSessionManager()
        {
            //_loginSession = new List<LoginSessionWithResponse>();
        }

        public PrMLoginSessionManager(ILoginSessionWithResponseDbServices loginServices, ITokenResponseDbServices tokenResponseServices, IPrMRequiredLoginSessionDbServices requiredLoginSessionDbServices)
        {
            _loginServices = loginServices;
            _tokenResponseServices = tokenResponseServices;
            _loginSessionServices = requiredLoginSessionDbServices;
        }

        public LoginSessionWithResponse CreateUserLoginSession(PrMUser user, PrMClient client)
        {
            var newObj = new LoginSessionWithResponse()
            {
                User = user,
                LoginSession = new PrMRequiredLoginSession()
                {
                    Client = client
                }
            };

            _loginServices.Create(newObj);

            return newObj;
        }

        public LoginSessionWithResponse FindByAuthorizationCode(string authorizationCode)
        {
            var obj = _loginServices.FindLoginSessionWithAuthorizationCode(authorizationCode);

            return obj;
        }

        public bool WhenLoginComplete(LoginSessionWithResponse session)
        {
            try
            {
                session.LoginSession.IsInLoginSession = false;
                _loginServices.Update(session);

                //_loginSession.Remove(session);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        public bool UpdateLoginSessionWithRelation(LoginSessionWithResponse session)
        {
            if (session.TokenResponse != null)
            {
                _tokenResponseServices.Update(session.TokenResponse);
            }
            if (session.LoginSession != null)
            {
                _loginSessionServices.Update(session.LoginSession);
            }

            return _loginServices.Update(session);
        }

        public TokenResponse CreateTokenResponse(LoginSessionWithResponse session)
        {
            var obj = new TokenResponse()
            {
                LoginSessionWithResponse = session,
            };

            _tokenResponseServices.Create(obj);
            //_loginServices.SaveChanges();

            return obj;
        }

        public bool UpdateInsideTokenResponse(LoginSessionWithResponse session)
        {
            if (session.TokenResponse != null)
            {
                _tokenResponseServices.Update(session.TokenResponse);
                return true;
            }
            return false;
        }

        public LoginSessionWithResponse FindByAccessToken(string accessToken)
        {
            var session = _loginServices.FindByAccessToken(accessToken);

            return session;
        }

        // TODO:
        // Create new session's object whenever a request involve with identity services is call, save it into a static list
        // - set for it authorization code when authorization code flow is initiated, add code challenger, add id token, access token expired time and access token follow this flow
        // - set for it id token and access token when implicit grant (with form_post or not) is initiated
        // =>  after everything is done following a particular flow which is used for authentication, save this session object to database
        // * Note: I don't want to save it when initiate authentication process and get it from database when it's call,
        //       : because, a particular session is used along with authentication process will be the latest, and search for it in db can create performance cost when this server is used long enough.
        //       : instead of search from db, save 100 session in used, and get it from memory (from authorization code, or id_token) is easier than query 100 object from 100.000 object table...


    }

    public interface IPrMLoginSessionManager
    {
        TokenResponse CreateTokenResponse(LoginSessionWithResponse loginSession);
        LoginSessionWithResponse CreateUserLoginSession(PrMUser user, PrMClient client);
        LoginSessionWithResponse FindByAuthorizationCode(string authorizationCode);
        LoginSessionWithResponse FindByAccessToken(string accessToken);
        bool UpdateLoginSessionWithRelation(LoginSessionWithResponse session);
        bool UpdateInsideTokenResponse(LoginSessionWithResponse session);
        bool WhenLoginComplete(LoginSessionWithResponse session);
    }
}
