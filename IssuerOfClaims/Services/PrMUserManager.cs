using IssuerOfClaims.Database;
using IssuerOfClaims.Models;
using PrMDbModels;
using PrMServerUltilities.Identity;
using System.Security.Claims;
using static PrMServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Services
{
    public class PrMUserManager : IPrMUserManager
    {
        public static Dictionary<PrMUser, ClaimsPrincipal> _UserClaims;
        public static Dictionary<PrMClient, ClaimsPrincipal> _ClientClaims;
        private IPrMUserDbServices _UserDbServices;
        private IPrMClientDbServices _ClientDbServices;

        private IPrMRequiredLoginSessionManager _loginSessionManager;

        static PrMUserManager()
        {
            _UserClaims = new Dictionary<PrMUser, ClaimsPrincipal>();
            _ClientClaims = new Dictionary<PrMClient, ClaimsPrincipal>();
        }

        public PrMUserManager(IPrMUserDbServices userDb, IPrMClientDbServices clientDb, IPrMRequiredLoginSessionManager loginSessionManager)
        {
            _UserDbServices = userDb;
            _ClientDbServices = clientDb;

            _loginSessionManager = loginSessionManager;
            //if (_Users.Count == 0)
            //{
            //    _UserDbServices.GetAllUsersIncludeAllRelation().ForEach(user =>
            //    {
            //        _Users.Add(user);
            //    });
            //}
            //if (_Clients.Count == 0)
            //{
            //    _ClientDbServices.GetAll().ForEach(client =>
            //    {
            //        _Clients.Add(client);
            //    });
            //}
        }

        /// <summary>
        /// TODO: by default of PrMUser's creation, userName cannot be null
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public PrMUser GetUserWithRelation(string userName)
        {
            return _UserDbServices.GetUserWithRelation(userName);
        }

        /// <summary>
        /// For now, use ClaimTypes of NetCore
        /// use when user login
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public ClaimsPrincipal GetClaimPrincipal(PrMUser user)
        {
            var claims = new List<Claim>
                            {
                                new Claim(ClaimTypes.Name, user.UserName),
                                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Password),
                                new Claim(ClaimTypes.Email, user.Email)
                            };
            user.PrMPermissions.ForEach(p =>
            {
                claims.Add(new Claim(ClaimTypes.Role, p.Role.RoleCode));
            });

            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC) });

            _UserClaims.Add(user, principal);
            return principal;
        }

        public ClaimsPrincipal GoogleInfoLogin(PrMUser user)
        {
            throw new NotImplementedException();
        }



        ///// <summary>
        ///// For now, use ClaimTypes of NetCore
        ///// </summary>
        ///// <param name="client"></param>
        ///// <returns></returns>
        //public ClaimsPrincipal GetClaimPrincipal(PrMClient client)
        //{
        //    var claims = new List<Claim>
        //    {
        //        new Claim(ClaimTypes.NameIdentifier, client.ClientId),
        //        new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.KnowledgeBasedAuthentication),
        //        // TODO: intend to use client role to seperate with user from PrMUser, still use ClaimPrincipal to store claims
        //        new Claim(ClaimTypes.Role, "client")
        //    };

        //    // TODO: for now, authentication type of identity is kba, I will find another implementation that can be used to replace
        //    var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, AuthenticationMethods.KnowledgeBasedAuthentication) });

        //    _ClientClaims.Add(client, principal);
        //    return principal;
        //}

        //public ClaimsPrincipal ClientLogin(PrMClient client)
        //{
        //    return _loginSessionManager.UpdateLoginSession();
        //}

        //public PrMClient GetClientByIdAndSecret(string clientId, string clientSecret)
        //{
        //    var client = _ClientDbServices.GetByIdAndSecret(clientId, clientSecret);

        //    return client;
        //}

        public PrMUser GetUserByClaimPrincipal(ClaimsPrincipal claims)
        {
            if (_UserClaims.ContainsValue(claims))
            {
                var obj = _UserClaims.FirstOrDefault(u => u.Value.Equals(claims)).Key;
                return obj;
            }

            return null;
        }

        public bool InitiateLoginSession(PrMClient client)
        {
            throw new NotImplementedException();
        }

        //public PrMClient GetClientById(string clientId)
        //{
        //    var client = _ClientDbServices.GetById(clientId);

        //    return client;
        //}

        public bool UpdateUser(PrMUser user)
        {
            return _UserDbServices.Update(user);
        }

        public bool UpdateSession(PrMRequiredLoginSession session)
        {
            return _loginSessionManager.UpdateLoginSession(session);
        }
    }

    public interface IPrMUserManager
    {
        PrMUser GetUserWithRelation(string userName);
        PrMUser GetUserByClaimPrincipal(ClaimsPrincipal claims);
        //PrMClient GetClientByIdAndSecret(string clientId, string clientSecret);
        //PrMClient GetClientById(string clientId);
        ClaimsPrincipal GetClaimPrincipal(PrMUser user);
        //ClaimsPrincipal GetClaimPrincipal(PrMClient user);
        ClaimsPrincipal GoogleInfoLogin(PrMUser user);
        //ClaimsPrincipal ClientLogin(PrMClient client);
        bool UpdateUser(PrMUser user);
        bool InitiateLoginSession(PrMClient client);
        bool UpdateSession(PrMRequiredLoginSession session);
    }
}
