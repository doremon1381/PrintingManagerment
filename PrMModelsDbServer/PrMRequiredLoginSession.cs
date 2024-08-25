using PrMDbModels;
#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("PrMRequiredLoginSession")]
    [PrimaryKey(nameof(Id))]
#endif
    public class PrMRequiredLoginSession: ModelBase
    {
        /// <summary>
        /// One time use only, for "Authorization code flow" or "hybrid flow"
        /// </summary>        
        public string? AuthorizationCode { get; set; } = null;
        /// <summary>
        /// From client
        /// </summary>
        public string? CodeChallenge { get; set; } = null;
        /// <summary>
        /// From client
        /// </summary>
        public string? CodeChallengeMethod { get; set; } = null;
        /// <summary>
        /// From client
        /// </summary>
        public string? Nonce { get; set; } = string.Empty;
        //public string? ClientState { get; set; } = string.Empty;
        public string? Scope { get; set; } = string.Empty;
        /// <summary>
        /// Value of this property is from TokenValidationPrinciples
        /// For sending token to client
        /// </summary>
        public string? TokenType { get; set; } = TokenValidationPrinciples.Bearer;
        /// <summary>
        /// TODO: when it was created, it will be the time when loginSession is initiated
        ///     : when everything is done, in token endpoint, set it to false, the loginSession is closed
        /// </summary>
        public bool IsInLoginSession { get; set; } = true;

        public bool IsOfflineAccess { get; set; } = false;

        [ForeignKey("LoginSessionWithResponseId")]
        public int? LoginSessionWithResponseId { get; set; }
        public LoginSessionWithResponse? LoginSessionWithResponse { get; set; }

#if DbServer
        //public int? UserId { get; set; }
        //public PrMUser? User { get; set; }

        /// <summary>
        /// TODO: intend to use this login session with client, cause 
        /// </summary>
        [ForeignKey("ClientId")]
        public int? ClientId { get; set; }
        public PrMClient? Client { get; set; }
#endif
    }


    public static class TokenValidationPrinciples
    {
        /// <summary>
        /// By default, and simplest
        /// </summary>
        public const string Bearer = "bearer";
        /// <summary>
        /// https://datatracker.ietf.org/doc/html/rfc9449
        /// </summary>
        public const string ProofOfPossession = "proof_of_possession";
    }
}
