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
    public class PrMRole: ModelBase
    {
        public string RoleCode { get; set; }
        public string RoleName { get; set; }

        public List<PrMPermission> PrMPermissions { get; set; }
    }
}
