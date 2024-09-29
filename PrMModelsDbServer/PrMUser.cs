﻿using Microsoft.AspNetCore.Identity;
using System;
#if IdentityServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if IdentityServer
    [Table("PrMUsers")]
    [PrimaryKey(nameof(Id))]
#endif
    public class PrMUser : IdentityUser<int>, IDbTable
    {
#if IdentityServer
        [Required]
#endif
        public string? PasswordHashSalt { get; set; } = null;
#if IdentityServer
        [Required]
#endif
        public string? FullName { get; set; } = string.Empty;
        public string? Name { get; set; } = string.Empty;
        public string? Gender { get; set; } = string.Empty;
        public DateTime? DateOfBirth { get; set; } = null;
        public string? Avatar { get; set; } = string.Empty;
        public bool IsEmailConfirmed { get; set; } = false;
        public DateTime CreateTime { get; set; } = DateTime.Now;
        public DateTime? UpdateTime { get; set; } = DateTime.Now;
#if IdentityServer
        [NotMapped]
#endif
        public override bool EmailConfirmed { get; set; }
        public override string? UserName { get; set; } = string.Empty;
        /// <summary>
        /// TODO: Will learn how to use it later
        /// </summary>
        public override string? SecurityStamp { get; set; } = null;
        public bool IsActive { get; set; } = false;
        ///// <summary>
        ///// TODO: to allow user-agent can use refresh-token to get new access token using token enpoint
        ///// </summary>
        //public bool IsOfflineAccess { get; set; } = true;
        public List<ConfirmEmail>? ConfirmEmails { get; set; } = new List<ConfirmEmail>();
        public List<PrMIdentityUserRole> PrMIdentityUserRoles { get; set; } = new List<PrMIdentityUserRole>();
        public List<TokenRequestHandler> TokenRequestHandlers { get; set; } = new List<TokenRequestHandler>();

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
