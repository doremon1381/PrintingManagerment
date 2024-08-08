#if DbServer
using Microsoft.EntityFrameworkCore;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("PrMUsers")]
    [PrimaryKey(nameof(Id))]
#endif
    public class PrMUser : ModelBase
    {
#if DbServer
        [Required]
#endif
        public string UserName { get; set; } = "";
#if DbServer
        [Required]
#endif
        public string Password { get; set; } = "";
#if DbServer
        [Required]
#endif
        public string PasswordHashSalt { get; set; } = "";
#if DbServer
        [Required]
#endif
        public string FullName { get; set; } = "";
        public DateTime? DateOfBirth { get; set; } = null;
        public string Avatar { get; set; } = "";
        public string Email { get; set; } = "";
        public bool IsEmailConfirmed { get; set; } = false;
        public DateTime CreateTime { get; set; } = DateTime.Now;
        public DateTime? UpdateTime { get; set; } = null;

        public string PhoneNumber { get; set; } = "";
        public int? TeamId { get; set; } = null;
        public bool IsActive { get; set; } = false;
        public List<PrMPermission> PrMPermissions { get; set; } = new List<PrMPermission>();
    }
}
