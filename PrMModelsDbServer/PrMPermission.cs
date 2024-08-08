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
    public class PrMPermission: ModelBase
    {
        public int PrMRoleId { get; set; }
        public int PrMUserId { get; set; }

        public PrMRole PrMRole { get; set; } = null;
        public PrMUser PrUser { get; set; } = null;
    }
}
