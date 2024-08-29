﻿using Microsoft.EntityFrameworkCore;
using PrMModels;

namespace PrintingManagermentServer.Database
{
    public class UserTokenDbServices : DbTableBase<UserToken>, IUserTokenDbServices
    {
        private DbSet<UserToken> _userTokenDbServices;

        public UserTokenDbServices(PrintingManagermentDbContext dbContext) : base(dbContext)
        {
            _userTokenDbServices = this._DbModels;
        }

        public UserToken FindByUsername(string userName)
        {
            var obj = _userTokenDbServices.FirstOrDefault(u => u.UserName.Equals(userName));
            return obj;
        }

        public UserToken FindByUsernameWithPermission(string userName)
        {
            var obj = _userTokenDbServices.Include(c => c.Permissions).ThenInclude(p => p.Role)
                 //.Include(c => c.LoginSessionWithTokens).ThenInclude(l => l.)
                 .FirstOrDefault(u => u.UserName.Equals(userName));
            return obj;
        }

        public List<UserToken> GetAllWithInclude()
        {
            var users = _userTokenDbServices.Include(u => u.Permissions).ThenInclude(p => p.Role).ToList();

            return users;
        }
    }

    public interface IUserTokenDbServices : IDbContextBase<UserToken>
    {
        UserToken FindByUsername(string userName);
        UserToken FindByUsernameWithPermission(string userName);
        List<UserToken> GetAllWithInclude();
    }
}
