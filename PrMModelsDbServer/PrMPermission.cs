using Microsoft.AspNetCore.Identity;
#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("PrMPermissions")]
    [PrimaryKey(nameof(Id))]
#endif
    // TODO: permission will be used for web server
    public class PrMPermission: IdentityUserRole<int>, IDbTable
    {
#if DbServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public int Id { get; set; }
        public override int RoleId { get; set; }
        public override int UserId { get; set; }

        public PrMRole Role { get; set; } = null;
        public UserToken User { get; set; } = null;
    }
}
