using Microsoft.AspNetCore.Identity;
#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("PrMRoles")]
    [PrimaryKey(nameof(Id))]
#endif
    public class PrMRole: IdentityRole<int>, IDbTable
    {
        public string RoleCode { get; set; }
        public string RoleName { get; set; }
#if DbServer
        [NotMapped]
#endif
        public override string? Name { get; set; }
#if DbServer
        [NotMapped]
#endif
        public override string? NormalizedName { get; set; }
        public override string? ConcurrencyStamp { get; set; }

        public List<PrMIdentityUserRole> PrMPermissions { get; set; }
    }
}
