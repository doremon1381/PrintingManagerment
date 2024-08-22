using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrintingManagermentServer.Models
{
    [Table("Roles")]
    [PrimaryKey(nameof(Id))]
    public class Role: ModelBase
    {
        public string RoleCode { get; set; }
        public string RoleName { get; set; }
        //[NotMapped]
        //public override string? Name { get; set; }
        //[NotMapped]
        //public override string? NormalizedName { get; set; }
        //public override string? ConcurrencyStamp { get; set; }

        public List<Permission> PrMPermissions { get; set; }
    }
}
