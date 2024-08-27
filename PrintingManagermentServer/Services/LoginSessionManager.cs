using PrintingManagermentServer.Database;
using PrintingManagermentServer.Models;

namespace PrintingManagermentServer.Services
{
    public class LoginSessionManager : ILoginSessionManager
    {
        private static List<LoginSessionWithToken> _LoginSession = new List<LoginSessionWithToken>();
        private ILoginSessionWithTokenDbServices _sessionWithTokenServices;

        public LoginSessionManager(ILoginSessionWithTokenDbServices sessionWithTokenServices)
        {
            _sessionWithTokenServices = sessionWithTokenServices;
        }

        internal static void AddDraft(LoginSessionWithToken session)
        {
            _LoginSession.Add(session);
        }

        public LoginSessionWithToken GetDraftFromState(string clientState)
        {
            var obj = _LoginSession.FirstOrDefault(l => l.LoginSession.ClientState == clientState);

            return obj;
        }

        public LoginSessionWithToken SaveDraft(LoginSessionWithToken session)
        {
            var current = _LoginSession.FirstOrDefault(s => s.LoginSession.ClientState.Equals(session.LoginSession.ClientState));
            if (_LoginSession.FirstOrDefault(s => s.LoginSession.ClientState.Equals(session.LoginSession.ClientState)) != null)
            {
                session.TokenResponse.LoginSessionWithToken = session;
                _sessionWithTokenServices.Create(session);
                _LoginSession.Remove(current);
            }

            return session;
        }

        public bool UpdateLoginSession(LoginSessionWithToken session)
        {
            return _sessionWithTokenServices.Update(session);
        }
    }

    public interface ILoginSessionManager
    {
        LoginSessionWithToken GetDraftFromState(string clientState);
        LoginSessionWithToken SaveDraft(LoginSessionWithToken session);
        bool UpdateLoginSession(LoginSessionWithToken session);
    }
}
