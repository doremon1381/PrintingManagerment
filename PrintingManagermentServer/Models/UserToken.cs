using Microsoft.EntityFrameworkCore;
using PrintingManagermentServer.Models;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrMModels
{
    [Table("UserTokens")]
    [PrimaryKey(nameof(Id))]
    public class UserToken: ModelBase
    {
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? FullName { get; set; } = string.Empty;
        public DateTime? DateOfBirth { get; set; } = null;
        public string? Avatar { get; set; } = null;
        public bool IsEmailConfirmed { get; set; } = false;
        //public string Roles { get; set; } = string.Empty;
        // TODO: it need
        //public List<LoginSession>
        public List<Permission> Permissions { get; set; } = new List<Permission>();
        public List<LoginSessionWithToken> LoginSessionWithTokens { get; set; } = new List<LoginSessionWithToken>();

    }
}
