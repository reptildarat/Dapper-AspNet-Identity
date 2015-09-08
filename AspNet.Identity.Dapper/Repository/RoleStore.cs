using System;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Identity.Dapper.Contracts.Repository;
using AspNet.Identity.Dapper.Repository.SqlServer;
using Dapper;
using Dapper.Contrib.Extensions;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Dapper.Repository
{

    /// <summary>
    ///     EntityFramework based implementation
    /// </summary>
    /// <typeparam name="TRole"></typeparam>
    public class RoleStore<TRole> : RoleStore<TRole, string, IdentityUserRole>, IQueryableRoleStore<TRole>
        where TRole : IdentityRole, new()
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        public RoleStore()
            : base(null)
        {
            
        }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="context"></param>
        public RoleStore(IConnectionRepository context)
            : base(context) {}
    }

    /// <summary>
    ///     EntityFramework based implementation
    /// </summary>
    /// <typeparam name="TRole"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    /// <typeparam name="TUserRole"></typeparam>
    public class RoleStore<TRole, TKey, TUserRole> : IQueryableRoleStore<TRole, TKey>
        where TUserRole : IdentityUserRole<TKey>, new()
        where TRole : IdentityRole<TKey, TUserRole>, new()
    {
        /// <summary>
        ///     If true will call SaveChanges after Create/Update/Delete
        /// </summary>
        public bool AutoSaveChanges { get; set; }

        private readonly IConnectionRepository _repository;

        public RoleStore(IConnectionRepository repository)
        {
            if(repository == null) throw new ArgumentNullException("repository");
            _repository = repository;
        }

        public void Dispose() {}

        public async Task CreateAsync(TRole role)
        {
            if (role == null) throw new ArgumentNullException("role");

            await _repository.WithConnectionAsync(db => db.InsertAsync(role));
        }

        public async Task UpdateAsync(TRole role)
        {
            if (role == null) throw new ArgumentNullException("role");

            await _repository.WithConnectionAsync(db => db.UpdateAsync(role));
        }

        public async Task DeleteAsync(TRole role)
        {
            if (role == null || role.Id == null) throw new ArgumentNullException("role");
            await _repository.WithConnectionAsync(db => db.DeleteAsync(role));
        }

        public async Task<TRole> FindByIdAsync(TKey roleId)
        {
            if (roleId == null || string.IsNullOrWhiteSpace(roleId.ToString()))
                throw new ArgumentNullException("roleId");

            return await _repository.WithConnectionAsync(db => db.Query<TRole>(_repository.FindRoleByIdAsync, 
                new {id = roleId}).FirstOrDefault());
        }

        public async Task<TRole> FindByNameAsync(string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName)) throw new ArgumentNullException("roleName");

            return await _repository.WithConnectionAsync(db => db.Query<TRole>(_repository.FindRoleByNameAsync,
                new { name = roleName }).FirstOrDefault());
        }

        public IQueryable<TRole> Roles
        {
            get { return _repository.WithConnection(db => db.GetAll<TRole>()).AsQueryable(); }
        }
    }
}