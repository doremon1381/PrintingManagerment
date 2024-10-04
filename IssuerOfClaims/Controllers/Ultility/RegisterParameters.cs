﻿using IssuerOfClaims.Extensions;
using Microsoft.AspNetCore.Http;
using ServerUltilities.Extensions;
using ServerUltilities.Identity;
using System.Web;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Controllers.Ultility
{
    public class RegisterParameters
    {
        #region requested parameters
        /// <summary>
        /// TODO: try to add nonce in flow, will check it late
        ///     : because "state" still RECOMMENDED in some case, so I will use it when it's provided for identity server
        /// </summary>
        public Parameter State { get; private set; } = new Parameter(AuthorizeRequest.State);

        /// <summary>
        /// TODO: base on scope, I will add claims in id token, so it will need to be verified with client's scope in memory or database
        ///    : Verify that a scope parameter is present and contains the openid scope value.
        ///    : (If no openid scope value is present, the request may still be a valid OAuth 2.0 request but is not an OpenID Connect request.)
        /// </summary>
        //public Parameter Scope { get; private set; } = new Parameter(AuthorizeRequest.Scope);

        // TODO: because in implicit grant flow, redirectUri is use to redirect to user-agent, 
        //     : in logically, client does not know it before user-agent send a redirect_uri to client
        //     : with browser's work, I think many browser can be user-agent, so it will be safe when client asks for redirect_uri from user-agent
        public Parameter RedirectUri { get; private set; } = new Parameter(AuthorizeRequest.RedirectUri);

        // TODO: need to compare with existing client in memory or database
        public Parameter ClientId { get; private set; } = new Parameter(AuthorizeRequest.ClientId);
        public Parameter UserName { get; private set; } = new Parameter(RegisterRequest.UserName);
        public Parameter Password { get; private set; } = new Parameter(RegisterRequest.Password);
        #endregion

        #region optional parameters
        /// <summary>
        /// TODO: try to add nonce in flow, will check it late
        ///     : because "nonce" still OPTIONAL in some case, so I will use it when it's provided for identity server
        /// </summary>
        public Parameter Nonce { get; private set; } = new Parameter(AuthorizeRequest.Nonce);
        public Parameter Email { get; private set; } = new Parameter(RegisterRequest.Email);
        public Parameter FirstName { get; private set; } = new Parameter(RegisterRequest.FirstName);
        public Parameter LastName { get; private set; } = new Parameter(RegisterRequest.LastName);
        public Parameter Roles { get; private set; } = new Parameter(RegisterRequest.Roles);
        public Parameter Gender { get; private set; } = new Parameter(RegisterRequest.Gender);
        #endregion

        public RegisterParameters(string[] requestQuery, IHeaderDictionary headers)
        {
            this.Nonce.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.Nonce));
            this.State.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.State));
            this.ClientId.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.ClientId));
            this.RedirectUri.SetValue(System.Uri.UnescapeDataString(requestQuery.GetFromQueryString(AuthorizeRequest.RedirectUri)));

            this.FirstName.SetValue(HttpUtility.UrlDecode(requestQuery.GetFromQueryString(RegisterRequest.FirstName).TrimStart().TrimEnd()));
            this.LastName.SetValue(HttpUtility.UrlDecode(requestQuery.GetFromQueryString(RegisterRequest.LastName).TrimStart().TrimEnd()));
            this.Email.SetValue(requestQuery.GetFromQueryString(RegisterRequest.Email));
            this.Gender.SetValue(requestQuery.GetFromQueryString(RegisterRequest.Gender));
            this.Roles.SetValue(requestQuery.GetFromQueryString(RegisterRequest.Roles));

            SetUserNameAndPassword(headers);
        }

        private void ValidateHeader(IHeaderDictionary headers)
        {
            if (headers["Register"][0] == null)
                throw new InvalidDataException(ExceptionMessage.REGISTER_INFORMATION_NULL_OR_EMPTY);
        }

        private void SetUserNameAndPassword(IHeaderDictionary headers)
        {
            ValidateHeader(headers);

            var userCredentials = headers["Register"][0];
            var userNamePassword = (userCredentials.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, "").Trim()).ToBase64Decode();

            // TODO: will need to validate username and password, from client and server
            string userName = userNamePassword.Split(":")[0];
            string password = userNamePassword.Split(":")[1];

            this.UserName.SetValue(userName);
            this.Password.SetValue(password);
        }
    }
}
