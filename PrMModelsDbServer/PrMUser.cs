using Microsoft.AspNetCore.Identity;
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
    public class PrMUser : IdentityUser<int>, IDbTable
    {
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
        public bool IsEmailConfirmed { get; set; } = false;
        public DateTime CreateTime { get; set; } = DateTime.Now;
        public DateTime? UpdateTime { get; set; } = DateTime.Now;
#if DbServer
        [NotMapped]
#endif
        public override bool EmailConfirmed { get; set; }
        public int? TeamId { get; set; } = null;
        public bool IsActive { get; set; } = false;
        ///// <summary>
        ///// A random value that must change whenever a user is persisted to the store
        ///// </summary>
        //public virtual string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
        ///// <summary>
        ///// Gets or sets the date and time, in UTC, when any user lockout ends.
        ///// </summary>
        ///// <remarks>
        ///// A value in the past means the user is not locked out.
        ///// </remarks>
        //public virtual DateTimeOffset? LockoutEnd { get; set; }
        ///// <summary>
        ///// Gets or sets the normalized user name for this user.
        ///// </summary>
        //public virtual string? NormalizedUserName { get; set; }
        ///// <summary>
        ///// Gets or sets the normalized email address for this user.
        ///// </summary>
        //public virtual string? NormalizedEmail { get; set; }
        public ConfirmEmail ConfirmEmail { get; set; }
        public List<PrMPermission> PrMPermissions { get; set; } = new List<PrMPermission>();
        public List<PrMUserClaim> PrMUserClaims { get; set; } = new List<PrMUserClaim>();
        public List<PrMUserLogin> PrMUserLogins { get; set; } = new List<PrMUserLogin>();

        public PrMUser()
        {
            this.AccessFailedCount = 0;
            this.PhoneNumber = string.Empty;
            this.PhoneNumberConfirmed = false;
            this.Email = string.Empty;
            this.LockoutEnabled = false;
            this.ConcurrencyStamp = string.Empty;
            this.LockoutEnd = null;
            this.NormalizedUserName = string.Empty;
            this.NormalizedEmail = string.Empty;
            this.SecurityStamp = string.Empty;
            this.TwoFactorEnabled = false;
        }
    }
}
