using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class ConfirmEmailDbServices : DbTableBase<ConfirmEmail>, IConfirmEmailDbServices
    {
        private DbSet<ConfirmEmail> _ConfirmEmails { get; set; }

        public ConfirmEmailDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            _ConfirmEmails = this._DbModels;
        }

        public ConfirmEmail CreateWithoutSaveChanges()
        {
            return new ConfirmEmail();
        }

        public ConfirmEmail GetByCode(string code)
        {
            var obj = _ConfirmEmails
                .Include(c => c.User)
                .FirstOrDefault(c => c.ConfirmCode == code);

            return obj;
        }
    }

    public interface IConfirmEmailDbServices: IDbContextBase<ConfirmEmail>
    {
        //ConfirmEmail Get(int id);
        ConfirmEmail CreateWithoutSaveChanges();
        ConfirmEmail GetByCode(string code);
    }
}
