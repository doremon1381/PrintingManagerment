using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrintingManagermentServer.Models
{
    [Table("Teams")]
    [PrimaryKey(nameof(Id))]
    public class Team: ModelBase
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int NumberOfMember { get; set; }
        public DateTime CreateTime { get; set; } = DateTime.Now;
        public DateTime? UpdateTime { get; set; }

        public TeamManager TeamManager { get; set; }
        public List<UserToken>? Users { get; set; }
    }
}
