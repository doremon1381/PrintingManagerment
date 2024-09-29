using Microsoft.EntityFrameworkCore;

namespace IssuerOfClaims.Database
{
    public abstract class DbTableBase<TEntity> : IDbContextBase<TEntity> where TEntity : class
    {
        protected DbSet<TEntity> _DbModels { get; set; }

        protected DbTableBase(IDbContextManager dbContext)
        {
            _dbSaveChanges = new DbSaveChanges(dbContext.DbSaveChanges);
            _isDisposed = new DbIsDisposed(dbContext.IsDisposed);
            _DbModels = dbContext.GetDbSet<TEntity>();
        }

        protected delegate void DbSaveChanges();
        protected DbSaveChanges _dbSaveChanges { get; private set; }

        protected delegate bool DbIsDisposed();
        protected DbIsDisposed _isDisposed { get; private set; }

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
                //return false;
                throw;
            }

            return true;
        }

        //public bool Add(TEntity model)
        //{
        //    try
        //    {
        //        this._DbModels.Add(model);
        //        this.SaveChanges();
        //    }
        //    catch (Exception)
        //    {
        //        //return false;
        //        throw;
        //    }

        //    return true;
        //}

        public bool Update(TEntity model)
        {
            try
            {
                this._DbModels.Update(model);
                this.SaveChanges();
            }
            catch (Exception)
            {
                //return false;
                throw;
            }

            return true;
        }

        public bool Delete(TEntity model)
        {
            try
            {
                this._DbModels.Remove(model);
                this.SaveChanges();
            }
            catch (Exception)
            {
                //return false;
                throw;
            }

            return true;
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
                // TODO:
                hasError = true;
                throw;
            }

            return !hasError;
        }

        public void SaveChanges()
        {
            this._dbSaveChanges.Invoke();
        }

        public bool IsDisposed()
        {
            return this._isDisposed.Invoke();
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
        //bool Add(TDbModel model);
        bool Update(TDbModel model);
        bool Delete(TDbModel model);
        bool AddMany(List<TDbModel> models);
        bool IsDisposed();
        void SaveChanges();
    }
}
