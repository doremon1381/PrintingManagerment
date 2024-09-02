using Microsoft.EntityFrameworkCore;

namespace PrintingManagermentServer.Database
{
    public abstract class DbTableBase<TEntity> : IDbContextBase<TEntity> where TEntity : class
    {
        protected DbSet<TEntity> _DbModels { get; set; }

        protected DbTableBase(PrintingManagermentDbContext dbContext)
        {
            _dbSaveChanges = new DbSaveChanges(dbContext.DbSaveChanges);
            _DbModels = dbContext.GetDbSet<TEntity>();
        }

        protected delegate void DbSaveChanges();
        protected DbSaveChanges _dbSaveChanges { get; set; }

        public List<TEntity> GetAll()
        {
            return this._DbModels.ToList();
        }

        public bool Create(TEntity model)
        {
            try
            {
                this._DbModels.Add(model);
                this.SaveChanges();
            }
            catch (Exception)
            {
                return false;
                //throw;
            }

            return true;
        }

        public bool Add(TEntity model)
        {
            try
            {
                this._DbModels.Add(model);
                this.SaveChanges();
            }
            catch (Exception)
            {
                return false;
                //throw;
            }

            return true;
        }

        public bool Update(TEntity model)
        {
            try
            {
                this._DbModels.Update(model);
                this.SaveChanges();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        public bool Delete(TEntity model)
        {
            try
            {
                this._DbModels.Remove(model);
                return true;
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public bool DeleteMany(List<TEntity> models)
        {
            try
            {
                this._DbModels.RemoveRange(models);
                return true;
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public bool IsTableEmpty()
        {
            return this._DbModels.Count() > 0 ? false : true;
        }

        public virtual bool AddMany(List<TEntity> models)
        {
            bool hasError = false;
            try
            {
                this._DbModels.AddRange(models);
                this.SaveChanges();
            }
            catch (System.Exception ex)
            {
                hasError = true;
            }

            return !hasError;
        }

        public void SaveChanges()
        {
            this._dbSaveChanges.Invoke();
        }
    }

    /// <summary>
    /// CRUD & something
    /// </summary>
    public interface IDbContextBase<TDbModel> where TDbModel : class
    {
        bool IsTableEmpty();
        List<TDbModel> GetAll();
        bool Create(TDbModel model);
        bool Add(TDbModel model);
        bool Update(TDbModel model);
        bool Delete(TDbModel model);
        bool DeleteMany(List<TDbModel> models);
        bool AddMany(List<TDbModel> models);
        void SaveChanges();
    }
}
