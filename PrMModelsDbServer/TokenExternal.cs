using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrMDbModels
{
    /// <summary>
    /// For example, google
    /// </summary>
    [Table("TokenExternals")]
    [PrimaryKey(nameof(Id))]
    public class TokenExternal : ModelBase
    {
        public string? AccessToken { get; set; } = null;
        public string? IdToken { get; set; } = null;
        public string? RefreshToken { get; set; } = null;

        /// <summary>
        /// For initiation
        /// </summary>
        public bool IsAccessTokenExpired { get; set; } = false;
        /// <summary>
        /// For initiation
        /// </summary>
        //public bool IsRefreshTokenExpired { get; set; } = false;

        /// <summary>
        /// TODO: set by seconds
        /// </summary>
        public DateTime? AccessTokenExpiried { get; set; } = null;
        /// <summary>
        /// TODO: set by seconds
        /// </summary>
        //public DateTime? RefreshTokenExpiried { get; set; } = null;

        [ForeignKey("LoginSessionWithResponseId")]
        public int? LoginSessionWithResponseId { get; set; }
        public LoginSessionWithResponse? LoginSessionWithResponse { get; set; }
    }
}
