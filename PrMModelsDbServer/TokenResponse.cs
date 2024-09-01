using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrMDbModels
{
    [Table("TokenResponses")]
    [PrimaryKey(nameof(Id))]
    public class TokenResponse : ModelBase
    {
        public string? AccessToken { get; set; } = null;
        public string? IdToken { get; set; } = null;
        public string? RefreshToken { get; set; } = null;

        ///// <summary>
        ///// For initiation
        ///// </summary>
        //public bool IsAccessTokenExpired { get; set; } = false;
        ///// <summary>
        ///// For initiation
        ///// </summary>
        //public bool IsRefreshTokenExpired { get; set; } = false;

        /// <summary>
        /// TODO: set by seconds
        /// </summary>
        public DateTime? AccessTokenExpiried { get; set; } = null;
        /// <summary>
        /// TODO: set by seconds
        /// </summary>
        public DateTime? RefreshTokenExpiried { get; set; } = null;

        [ForeignKey("TokenRequestHandlerId")]
        public int? TokenRequestHandlerId { get; set; }
        public TokenRequestHandler? TokenRequestHandler { get; set; }
    }
}
