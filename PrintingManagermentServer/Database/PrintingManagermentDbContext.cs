using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PrintingManagermentServer.Models;
using PrMModels;

namespace PrintingManagermentServer.Database
{
    public class PrintingManagermentDbContext : DbContext, IPrintingManagermentDbContext
    {
        private ILogger<PrintingManagermentDbContext> _logger;
        private DbContextOptions _options;

        public DbSet<UserToken> UserTokens { get; set; }
        public DbSet<LoginSession> LoginSessions { get; set; }
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<LoginSessionWithToken> LoginSessionWithTokens { get; set; }
        public DbSet<TokenResponse> TokenResponses { get; set; }

        public PrintingManagermentDbContext(DbContextOptions<PrintingManagermentDbContext> options, ILogger<PrintingManagermentDbContext> logger)
            : base(options)
        {
            _options = options;
            _logger = logger;

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

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<LoginSessionWithToken>()
                .HasOne(l => l.LoginSession)
                .WithOne(s => s.LoginSessionWithToken)
                .HasForeignKey<LoginSession>(l => l.LoginSessionWithTokenId);

            modelBuilder.Entity<LoginSessionWithToken>()
                .HasOne(l => l.TokenResponse)
                .WithOne(t => t.LoginSessionWithToken)
                .HasForeignKey<TokenResponse>(t => t.LoginSessionWithTokenId);

        }
    }

    internal interface IPrintingManagermentDbContext
    {
    }

    // TODO: for migration
    public class YourDbContextFactory : IDesignTimeDbContextFactory<PrintingManagermentDbContext>
    {
        public PrintingManagermentDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<PrintingManagermentDbContext>();
            optionsBuilder.UseSqlServer("Server=DESKTOP-2TRDKFE\\;Database=PrintingManagermentBusiness;trusted_connection=true;TrustServerCertificate=True");

            // TODO: logger as parameter is null for now
            return new PrintingManagermentDbContext(optionsBuilder.Options, null);
        }
    }
}
