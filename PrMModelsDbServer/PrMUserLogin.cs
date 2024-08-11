using Microsoft.AspNetCore.Identity;
#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("PrMUserLogins")]
    [PrimaryKey(nameof(Id))]
#endif
    public class PrMUserLogin: IdentityUserLogin<int>, IDbTable
    {
#if DbServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public int Id { get; set; }

        public PrMUser User { get; set; }

#if DbServer
        [Required]
#endif
        public string AccessToken { get; set; } = string.Empty;
#if DbServer
        [Required]
#endif
        public string RefreshToken { get; set; } = string.Empty;

        public DateTime? AccessTokenExpiried { get; set; } = null;
        public DateTime? RefreshTokenExpiried { get; set; } = null;
    }
}
