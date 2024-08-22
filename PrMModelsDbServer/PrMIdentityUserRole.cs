using Microsoft.AspNetCore.Identity;
#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("PrMIdentityUserRoles")]
    [PrimaryKey(nameof(Id))]
#endif
    public class PrMIdentityUserRole : IdentityUserRole<int>, IDbTable
    {
#if DbServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public int Id { get; set; }
        public override int RoleId { get; set; }
        public override int UserId { get; set; }

        public PrMRole Role { get; set; } = null;
        public PrMUser User { get; set; } = null;
    }
}
