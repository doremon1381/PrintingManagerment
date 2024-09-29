using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using PrMDbModels;
using System.Reflection;

namespace IssuerOfClaims.Database
{
    public class DbContextManager : DbContext, IDbContextManager
    {

        private ILogger<DbContextManager> _logger;
        private DbContextOptions _options;
        //private IConfiguration _configuration;

        #region DbSet needs to be add in this DbContext to prevent an error of DbSet is not existed in this context (I think it means in this DbContext class) when using later
        public DbSet<PrMUser> PrMUsers { get; set; }
        public DbSet<PrMRole> PrMRoles { get; set; }
        public DbSet<PrMIdentityUserRole> IdentityUserRoles { get; set; }
        public DbSet<PrMClient> PrMClients { get; set; }
        public DbSet<ConfirmEmail> ConfirmEmails { get; set; }
        public DbSet<TokenExternal> TokenExternals { get; set; }
        public DbSet<TokenRequestSession> PrMRequiredLoginSessions { get; set; }
        public DbSet<TokenRequestHandler> LoginSessionWithResponses { get; set; }
        public DbSet<TokenResponse> TokenResponses { get; set; }
        #endregion

        public DbContextManager(DbContextOptions<DbContextManager> options, ILogger<DbContextManager> logger)
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

        // Using Type: 5.0.16.0  EntityFrameworkCore.DbContext (confirm if working with any core library upgrades)

        public bool IsDisposed()
        {
            bool result = true;
            var typeDbContext = typeof(DbContext);
            var isDisposedTypeField = typeDbContext.GetField("_disposed", BindingFlags.NonPublic | BindingFlags.Instance);

            if (isDisposedTypeField != null)
            {
                result = (bool)isDisposedTypeField.GetValue(this);
            }

            return result;
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

            modelBuilder.Entity<TokenRequestHandler>()
                .HasOne(c => c.TokenRequestSession)
                .WithOne(l => l.TokenRequestHandler)
                .HasForeignKey<TokenRequestSession>(l => l.TokenRequestHandlerId);

            modelBuilder.Entity<TokenRequestHandler>()
                .HasOne(c => c.TokenResponse)
                .WithOne(t => t.TokenRequestHandler)
                .HasForeignKey<TokenResponse>(t => t.TokenRequestHandlerId);

            modelBuilder.Entity<TokenRequestHandler>()
                .HasOne(c => c.TokenExternal)
                .WithOne(t => t.TokenRequestHandler)
                .HasForeignKey<TokenExternal>(t => t.TokenRequestHandlerId);

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

    public interface IDbContextManager
    {
        void DbSaveChanges();
        bool IsDisposed();
        DbSet<TEntity> GetDbSet<TEntity>() where TEntity : class;
    }

    // TODO: for migration
    public class YourDbContextFactory : IDesignTimeDbContextFactory<DbContextManager>
    {
        public DbContextManager CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<DbContextManager>();
            optionsBuilder.UseSqlServer("Server=DESKTOP-2TRDKFE\\;Database=PrintingManagermentIdentity;trusted_connection=true;TrustServerCertificate=True");

            // TODO: logger as parameter is null for now
            return new DbContextManager(optionsBuilder.Options, null);
        }
    }
}
