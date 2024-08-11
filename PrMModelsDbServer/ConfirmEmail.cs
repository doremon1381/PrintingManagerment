#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
#endif
using PrMDbModels;

namespace PrMDbModels
{
#if DbServer
    [Table("ConfirmEmails")]
    [PrimaryKey(nameof(Id))]
#endif
    public class ConfirmEmail : ModelBase
    {
        public int? UserId { get; set; } = null;
#if DbServer
        [Required]
#endif
        public string ConfirmCode { get; set; } = "";
        public DateTime? ExpiryTime { get; set; } = null;
        public DateTime CreatedTime { get; set; } = DateTime.Now;
        public bool IsConfirmed { get; set; } = false;

        public PrMUser? User { get; set; } = null;
    }
}
