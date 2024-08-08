namespace IssuerOfClaims.Services
{
    public class PrMIdentityServer: IPrMIdentityServer
    {
        private readonly IServiceCollection _Services;

        public PrMIdentityServer(IServiceCollection services) 
        { 
            _Services = services;
        }
    }

    public interface IPrMIdentityServer
    {
    }
}
