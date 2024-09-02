using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrMDbModels
{
    [Table("Permissions")]
    [PrimaryKey(nameof(Id))]
    // TODO: permission will be used for web server
    public class Permission: IdentityUserRole<int>, IDbTable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public override int RoleId { get; set; }
        public override int UserId { get; set; }

        public Role Role { get; set; } = null;
        public UserToken User { get; set; } = null;
    }
}
