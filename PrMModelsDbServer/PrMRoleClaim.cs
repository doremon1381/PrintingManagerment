using Microsoft.AspNetCore.Identity;
#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("PrMRoleClaims")]
    [PrimaryKey(nameof(Id))]
#endif
    public class PrMRoleClaim: IdentityRoleClaim<int>, IDbTable
    {
#if DbServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public override int Id { get; set; }
#if DbServer
        [ForeignKey("RoleId")]
#endif
        public override int RoleId { get; set; }
        public PrMRole Role { get; set; }
    }
}
