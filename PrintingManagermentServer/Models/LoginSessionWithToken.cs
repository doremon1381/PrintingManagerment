using Microsoft.EntityFrameworkCore;
using PrMModels;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrintingManagermentServer.Models
{
    [Table("LoginSessionWithTokens")]
    [PrimaryKey(nameof(Id))]
    public class LoginSessionWithToken: ModelBase
    {
        public int? UserTokenId { get; set; }
        public UserToken? UserToken { get; set; }

        public LoginSession LoginSession {get;set;}
        public TokenResponse TokenResponse { get; set; }

    }
}
