using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrMDbModels
{
    [Table("LoginSessions")]
    [PrimaryKey(nameof(Id))]
    public class LoginSession : ModelBase
    {
        /// <summary>
        /// One time use only, for "Authorization code flow" or "hybrid flow"
        /// </summary>        
        public string? CodeVerifier { get; set; } = string.Empty;
        /// <summary>
        /// From client
        /// </summary>
        public string? CodeChallenge { get; set; } = string.Empty;
        /// <summary>
        /// From client
        /// </summary>
        public string? CodeChallengeMethod { get; set; } = string.Empty;
        
        /// <summary>
        /// TODO: for user-agent
        /// </summary>
        public string? ClientState { get; set; } = string.Empty;
        public string? Nonce { get; set; } = string.Empty;

        public bool IsInLoginSession { get; set; } = true;

        public int? LoginSessionWithTokenId { get; set; }
        public LoginSessionWithToken? LoginSessionWithToken { get; set; }
        /// <summary>
        /// Value of this property is from TokenValidationPrinciples
        /// For sending token to client
        /// </summary>
        public string? TokenType { get; set; } = TokenValidationPrinciples.Bearer;
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
