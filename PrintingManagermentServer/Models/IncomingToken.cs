using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrintingManagermentServer.Models
{
    /// <summary>
    /// TODO: Using for saving token from identityserver
    /// </summary>
    [Table("IncomingTokens")]
    [PrimaryKey(nameof(Id))]
    public class IncomingToken : ModelBase
    {
        public string? AccessToken { get; set; } = null;
        public string? IdToken { get; set; } = null;
        public string? RefreshToken { get; set; } = null;

        public DateTime? AccessTokenExpiried { get; set; } = null;
        // TODO: because client will not know it
        //public DateTime? RefreshTokenExpiried { get; set; } = null;

        public int? LoginSessionWithTokenId { get; set; }
        public LoginSessionWithToken? LoginSessionWithToken { get; set; }
    }
}
