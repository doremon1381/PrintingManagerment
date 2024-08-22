using PrintingManagermentServer.Models;

namespace PrintingManagermentServer.Services
{
    public class LoginSessionManager: ILoginSessionManager
    {
        private static List<LoginSession> _LoginSession = new List<LoginSession>();

        public LoginSessionManager()
        {

        }

        internal static void AddDraft(LoginSession session)
        {
            _LoginSession.Add(session); 
        }

        public LoginSession GetDraftFromState(string clientState)
        {
            var obj = _LoginSession.FirstOrDefault(l => l.ClientState == clientState);

            return obj;
        }
    }

    public interface ILoginSessionManager
    {
        LoginSession GetDraftFromState(string clientState);
    }
}
