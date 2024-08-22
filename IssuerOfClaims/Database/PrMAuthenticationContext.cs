using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMAuthenticationContext : DbContext, IPrMAuthenticationContext
    {

        private ILogger<PrMAuthenticationContext> _logger;
        private DbContextOptions _options;
        //private IConfiguration _configuration;

        #region DbSet needs to be add in this DbContext to prevent an error of DbSet is not existed in this context (I think it means in this DbContext class) when using later
        public DbSet<PrMUser> PrMUsers { get; set; }
        public DbSet<PrMRole> PrMRoles { get; set; }
        public DbSet<PrMIdentityUserRole> IdentityUserRoles { get; set; }
        public DbSet<PrMClient> PrMClients { get; set; }
        public DbSet<ConfirmEmail> ConfirmEmails { get; set; }
        public DbSet<TokenExternal> TokenExternals { get; set; }
        public DbSet<PrMRequiredLoginSession> PrMRequiredLoginSessions { get; set; }
        public DbSet<LoginSessionWithResponse> LoginSessionWithResponses { get; set; }
        public DbSet<TokenResponse> TokenResponses { get; set; }
        #endregion

        public PrMAuthenticationContext(DbContextOptions<PrMAuthenticationContext> options, ILogger<PrMAuthenticationContext> logger)
            : base(options)
        {
            _options = options;
            _logger = logger;

            //_configuration = configuration;

        }

        public void DbSaveChanges()
        {
            this.SaveChanges();
        }

        public DbSet<TEntity> GetDbSet<TEntity>() where TEntity : class
        {
            if (typeof(IDbTable).IsAssignableFrom(typeof(TEntity)))
            {
                return this.Set<TEntity>();
            }

            // TODO: for learning
            _logger.LogInformation($"GetDbSet is called!");
            // TODO: will change 
            return null;
        }

#if (DEBUG || RELEASE)
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //modelBuilder.Entity<CustomClient>()
            //    .Property(x => x.Properties)
            //    .HasConversion(
            //        x => JsonConvert.SerializeObject(x),
            //        x => JsonConvert.DeserializeObject<IDictionary<string, string>>(x),
            //        // TODO: need to learn about compare
            //        new ValueComparer<IDictionary<string, string>>(
            //            (c1, c2) => c1.SequenceEqual(c2),
            //            c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
            //            c => c.ToDictionary<string,string>()));
            //modelBuilder.Entity<PrMClient>()
            //    .Property(e => e.ClientSecrets)
            //    .HasConversion(
            //        v => string.Join(',', v),
            //        v => v.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList());
            //modelBuilder.Entity<PrMClient>()
            //    .Property(e => e.AllowedGrantTypes)
            //    .HasConversion(
            //        v => string.Join(',', v),
            //        v => v.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList());
            //modelBuilder.Entity<PrMClient>()
            //    .Property(e => e.RedirectUris)
            //    .HasConversion(
            //        v => string.Join(',', v),
            //        v => v.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList());
            //modelBuilder.Entity<PrMClient>()
            //    .Property(e => e.PostLogoutRedirectUris)
            //    .HasConversion(
            //        v => string.Join(',', v),
            //        v => v.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList());
            //modelBuilder.Entity<PrMClient>()
            //    .Property(e => e.AllowedScopes)
            //    .HasConversion(
            //        v => string.Join(',', v),
            //        v => v.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList());

            //modelBuilder.Entity<PrMRole>()
            //    .HasMany(a => a.RoleClaims)
            //    .WithOne(c => c.Role)
            //    .HasForeignKey(c => c.RoleId);

            modelBuilder.Entity<PrMClient>()
                .HasMany(c => c.LoginSessions)
                .WithOne(l => l.Client)
                .HasForeignKey(c => c.ClientId);

            modelBuilder.Entity<LoginSessionWithResponse>()
                .HasOne(c => c.LoginSession)
                .WithOne(l => l.LoginSessionWithResponse)
                .HasForeignKey<PrMRequiredLoginSession>(l => l.LoginSessionWithResponseId);

            modelBuilder.Entity<LoginSessionWithResponse>()
                .HasOne(c => c.TokenResponse)
                .WithOne(t => t.LoginSessionWithResponse)
                .HasForeignKey<TokenResponse>(t => t.LoginSessionWithResponseId);

            modelBuilder.Entity<LoginSessionWithResponse>()
                .HasOne(c => c.TokenExternal)
                .WithOne(t => t.LoginSessionWithResponse)
                .HasForeignKey<TokenExternal>(t => t.LoginSessionWithResponseId);

            base.OnModelCreating(modelBuilder);
        }
#else 
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlServer("Server=DESKTOP-2TRDKFE\\;Database=LAuthentication;trusted_connection=true;TrustServerCertificate=True");
            base.OnConfiguring(optionsBuilder);
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //modelBuilder.Entity<CustomClient>()
            //    .Property(x => x.Properties)
            //    .HasConversion(
            //        x => JsonConvert.SerializeObject(x),
            //        x => JsonConvert.DeserializeObject<IDictionary<string, string>>(x));
            //        // TODO: need to learn about compare
            //        new ValueComparer<IDictionary<string, string>>(
            //            (c1, c2) => c1.SequenceEqual(c2),
            //            c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
            //            c => c.ToDictionary<string,string>()));
            base.OnModelCreating(modelBuilder);
        }
#endif
    }

    public interface IPrMAuthenticationContext
    {
        void DbSaveChanges();
        DbSet<TEntity> GetDbSet<TEntity>() where TEntity : class;
    }

    // TODO: for migration
    public class YourDbContextFactory : IDesignTimeDbContextFactory<PrMAuthenticationContext>
    {
        public PrMAuthenticationContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<PrMAuthenticationContext>();
            optionsBuilder.UseSqlServer("Server=DESKTOP-2TRDKFE\\;Database=PrintingManagermentIdentity;trusted_connection=true;TrustServerCertificate=True");

            // TODO: logger as parameter is null for now
            return new PrMAuthenticationContext(optionsBuilder.Options, null);
        }
    }
}
