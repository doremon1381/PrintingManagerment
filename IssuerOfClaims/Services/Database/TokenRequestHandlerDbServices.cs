using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class TokenRequestHandlerDbServices : DbTableBase<TokenRequestHandler>, ITokenRequestHandlerDbServices
    {
        private readonly DbSet<TokenRequestHandler> _tokenRequestHandlers;
        private readonly ILogger _logger;

        public TokenRequestHandlerDbServices(IDbContextManager dbContext, ILoggerFactory logger) 
            : base(dbContext)
        {
            _tokenRequestHandlers = _DbModels;

            _logger = logger.CreateLogger("TokenRequestHandlerServices");
        }

        public TokenRequestHandler FindByAccessToken(string accessToken)
        {
            var obj = _tokenRequestHandlers
                .Include(l => l.User)
                .Include(l => l.TokenResponse)
                .Include(l => l.TokenRequestSession)
                .Include(l => l.TokenExternal)
                .FirstOrDefault(l => l.TokenResponse.AccessToken.Equals(accessToken));
            _logger.LogInformation($"current thread id is {Thread.CurrentThread.ManagedThreadId}");
            return obj;
        }

        public TokenRequestHandler FindByRefreshToken(string refreshToken)
        {
            var obj = _tokenRequestHandlers
                .Include(l => l.User)
                .Include(l => l.TokenResponse)
                .Include(l => l.TokenRequestSession)
                .Include(l => l.TokenExternal)
                .FirstOrDefault(l => l.TokenResponse.RefreshToken.Equals(refreshToken));
            _logger.LogInformation($"current thread id is {Thread.CurrentThread.ManagedThreadId}");

            return obj;
        }

        public TokenRequestHandler FindByAuthorizationCode(string authorizationCode)
        {
            var obj = _tokenRequestHandlers
                .Include(l => l.User)
                .Include(l => l.TokenResponse)
                .Include(l => l.TokenRequestSession).ThenInclude(t => t.Client)
                .Include(l => l.TokenExternal).ToList()
                .Find(l => l.TokenRequestSession != null && l.TokenRequestSession.AuthorizationCode.Equals(authorizationCode)) ?? new TokenRequestHandler();
            _logger.LogInformation($"current thread id is {Thread.CurrentThread.ManagedThreadId}");

            return obj;
        }

        public TokenRequestHandler CreateTokenRequestHandler()
        {
            var obj = new TokenRequestHandler();
            this.Create(obj);

            return obj;
        }
    }

    public interface ITokenRequestHandlerDbServices: IDbContextBase<TokenRequestHandler>
    {
        //TokenRequestHandler FindByAccessToken(string accessToken);
        //TokenRequestHandler FindByRefreshToken(string refreshToken);
        //TokenRequestHandler FindLoginSessionWithAuthorizationCodeAsync(string authorizationCode);
        TokenRequestHandler FindByAuthorizationCode(string authorizationCode);
        TokenRequestHandler FindByAccessToken(string accessToken);
        TokenRequestHandler FindByRefreshToken(string refreshToken);
        TokenRequestHandler CreateTokenRequestHandler();
    }
}
