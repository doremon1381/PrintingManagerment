﻿using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrMDbModels
{
    [Table("UserTokens")]
    [PrimaryKey(nameof(Id))]
    public class UserToken: IdentityUser<int>, IDbTable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public override string UserName { get; set; } = string.Empty;
        public override string Email { get; set; } = string.Empty;
        public string? FullName { get; set; } = string.Empty;
        public string? Gender { get; set; } = string.Empty;
        public override string? PhoneNumber { get; set; } = string.Empty;
        public DateTime? DateOfBirth { get; set; } = null;
        public DateTime? UpdateTime { get; set; } = DateTime.Now;
        public DateTime CreateTime { get; set; } = DateTime.Now;

        public string? Avatar { get; set; } = null;
        public bool IsEmailConfirmed { get; set; } = false;

        public int? TeamId { get; set; }
        public Team? Team { get; set; }

        public List<TeamManager>? TeamManager { get; set; }

        #region ignore
        //[NotMapped]
        public override string? NormalizedUserName { get; set; } = string.Empty;
        //[NotMapped]
        public override string? NormalizedEmail { get; set; } = string.Empty;
        [NotMapped]
        public override bool EmailConfirmed { get; set; } = false;
        [NotMapped]
        public override string? PasswordHash { get; set; }
        [NotMapped]
        public override bool PhoneNumberConfirmed { get; set; }
        [NotMapped]
        public override bool TwoFactorEnabled { get; set; }
        //[NotMapped]
        public override DateTimeOffset? LockoutEnd { get; set; }
        //[NotMapped]
        public override bool LockoutEnabled { get; set; }
        //[NotMapped]
        public override int AccessFailedCount { get; set; }
        #endregion

        //public string Roles { get; set; } = string.Empty;
        // TODO: it need
        //public List<LoginSession>
        public List<Permission> Permissions { get; set; } = new List<Permission>();
        public List<LoginSessionWithToken> LoginSessionWithTokens { get; set; } = new List<LoginSessionWithToken>();

    }
}
