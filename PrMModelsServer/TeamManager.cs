using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrMDbModels
{
    [Table("TeamManagers")]
    [PrimaryKey(nameof(Id))]
    public class TeamManager: ModelBase
    {
        public int TeamId { get; set; }
        public int ManagerId { get; set; }

        public Team Team { get; set; }
        public UserToken Manager { get; set; }
    }
}
