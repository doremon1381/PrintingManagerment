using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrMDbModels
{
    [Table("LoginSessionWithTokens")]
    [PrimaryKey(nameof(Id))]
    public class LoginSessionWithToken: ModelBase
    {
        public int? UserTokenId { get; set; }
        public UserToken? UserToken { get; set; }

        public LoginSession LoginSession {get;set;}
        public TokenResponse TokenResponse { get; set; }
        public IncomingToken IncomingToklen { get; set; }

    }
}
