using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrintingManagermentServer.Models
{
    [Table("TokenResponses")]
    [PrimaryKey(nameof(Id))]
    public class TokenResponse: ModelBase
    {
        public string? AccessToken { get; set; } = null;
        public string? IdToken { get; set; } = null;
        public string? RefreshToken { get; set; } = null;

        public DateTime? AccessTokenExpiried { get; set; } = null;
        public DateTime? RefreshTokenExpiried { get; set; } = null;

        public int? LoginSessionWithTokenId { get; set; }
        public LoginSessionWithToken? LoginSessionWithToken { get; set; }
    }
}
