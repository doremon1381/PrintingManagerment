using IssuerOfClaims.Database.Model;
using Microsoft.EntityFrameworkCore;
using PrMDbModels;

namespace IssuerOfClaims.Database
{
    public class PrMUserDbServices : DbTableBase<PrMUser>, IPrMUserDbServices
    {
        private DbSet<PrMUser> _PrMUsers { get; set; }
        public PrMUserDbServices(IPrMAuthenticationContext dbContext) : base(dbContext)
        {
            _PrMUsers = this._DbModels;
        }

        public PrMUser GetByUserNameAndPassword(string userName, string password)
        {
            var user = _PrMUsers.First(user => user.UserName.Equals(userName));

            return user;
        }

        public PrMUser GetByUserName(string userName)
        {
            var user = _PrMUsers.First(user => user.UserName.Equals(userName));

            return user;
        }

        public bool CreateNewUser(PrMUser user)
        {
            try
            {
                _PrMUsers.Add(user);
                this.SaveChanges();
            }
            catch (Exception ex)
            {
                return false;
            }

            return true;
        }
    }

    public interface IPrMUserDbServices
    {
        bool CreateNewUser(PrMUser user);
        public PrMUser GetByUserName(string userName);
    }
}
