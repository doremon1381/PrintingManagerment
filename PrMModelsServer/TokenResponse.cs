using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrMDbModels
{
    /// <summary>
    /// Use for saving token which is used for sending to user-agent
    /// </summary>
    [Table("TokenResponses")]
    [PrimaryKey(nameof(Id))]
    public class TokenResponse: ModelBase
    {
        /// <summary>
        /// This access token will has form as jwt token
        /// </summary>
        public string? AccessToken { get; set; } = null;
        //public string? IdToken { get; set; } = null;
        //public string? RefreshToken { get; set; } = null;

        public DateTime? AccessTokenExpiried { get; set; } = null;
        // TODO: because client will not know it
        //public DateTime? RefreshTokenExpiried { get; set; } = null;

        public int? LoginSessionWithTokenId { get; set; }
        public LoginSessionWithToken? LoginSessionWithToken { get; set; }
    }
}
