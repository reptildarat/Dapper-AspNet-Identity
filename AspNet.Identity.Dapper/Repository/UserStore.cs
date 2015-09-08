using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Identity.Dapper.Contracts.Repository;
using AspNet.Identity.Dapper.Repository.SqlServer;
using Dapper;
using Dapper.Contrib.Extensions;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Dapper.Repository
{

    public class UserStore<TUser> :
       UserStore<TUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>,
       IUserStore<TUser> where TUser : IdentityUser
    {

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="repository"></param>
        public UserStore(IConnectionRepository repository)
            : base(repository) {}
    }

    public class UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> :
       IUserLoginStore<TUser, TKey>,
       IUserClaimStore<TUser, TKey>,
       IUserRoleStore<TUser, TKey>,
       IUserPasswordStore<TUser, TKey>,
       IUserSecurityStampStore<TUser, TKey>,
       IQueryableUserStore<TUser, TKey>,
       IUserEmailStore<TUser, TKey>,
       IUserPhoneNumberStore<TUser, TKey>,
       IUserTwoFactorStore<TUser, TKey>,
       IUserLockoutStore<TUser, TKey>
        where TKey : IEquatable<TKey>
        where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>
        where TRole : IdentityRole<TKey, TUserRole>
        where TUserLogin : IdentityUserLogin<TKey>, new()
        where TUserRole : IdentityUserRole<TKey>, new()
        where TUserClaim : IdentityUserClaim<TKey>, new()
    {
        private readonly IConnectionRepository _repository;
        private TUser _deferUser;
        private int _isDirty;
        public UserStore(IConnectionRepository repository)
        {
            if(repository == null) throw new ArgumentNullException("repository");
            AutoSaveChanges = true;
            _repository = repository;
            _isDirty = 0;
        }



        /// <summary>
        ///     If true will call SaveChanges after Create/Update/Delete
        /// </summary>
        public bool AutoSaveChanges { get; set; }

        public virtual async Task CreateAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (AutoSaveChanges & _isDirty > 0 & _deferUser != null)
            {
                await _repository.WithConnectionAsync(db => db.InsertAsync(_deferUser));
                return;
            }

            await _repository.WithConnectionAsync(db => db.InsertAsync(user));
        }

        public virtual async Task UpdateAsync(TUser user)
        {
            if (user == null || user.Id == null) throw new ArgumentNullException("user");
            if (AutoSaveChanges & _isDirty > 0 & _deferUser != null)
            {
                await _repository.WithConnectionAsync(db => db.UpdateAsync(_deferUser));
                return;
            }

            await _repository.WithConnectionAsync(db => db.Update(user));
        }

        public virtual async Task DeleteAsync(TUser user)
        {
            if(user == null || user.Id == null) throw new ArgumentNullException("user");
            if (AutoSaveChanges & _isDirty > 0 & _deferUser != null)
            {
                await _repository.WithConnectionAsync(db => db.DeleteAsync(_deferUser));
                return;
            }

            await _repository.WithConnectionAsync(db => db.DeleteAsync(user));
        }

        public virtual async Task<TUser> FindByIdAsync(TKey userId)
        {
            if (userId == null) return null;

            return
                await
                    _repository.WithConnectionAsync(
                        db => db.Query<TUser>(_repository.FindIdentityUserById, new {id = userId}).FirstOrDefault());
        }

        public virtual Task<TUser> FindByNameAsync(string userName)
        {
            if (string.IsNullOrEmpty(userName)) throw new ArgumentNullException("userName");
            return _repository.WithConnectionAsync
                (db => db.Query<TUser>(_repository.FindByName, new { user = userName}).FirstOrDefault());
        }

        public virtual Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null || login == null) throw new ArgumentNullException("user");

            return _repository.WithConnectionAsync(db => db.InsertAsync(new TUserLogin
            {
                UserId = user.Id,
                ProviderKey = login.ProviderKey,
                LoginProvider = login.LoginProvider
            }));
        }

        public virtual async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null || user.Id == null || login == null || login.ProviderKey == null)
                throw new ArgumentNullException("login");

            await _repository.WithConnectionAsync(db => db.ExecuteAsync(_repository.RemoveLogin, 
                new {provider = login.LoginProvider, key = login.ProviderKey, userId = user.Id}));
        }

        public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            if (user == null || user.Id == null) throw new ArgumentNullException("user");

            var theUsers = await _repository.WithConnectionAsync(db => db.QueryAsync<TUserLogin>
                (_repository.GetLogins, new {id = user.Id}));
            var userLoginList = new List<UserLoginInfo>();

            if (theUsers == null || !theUsers.Any()) return userLoginList;

            userLoginList.AddRange(theUsers.Select(theUser => new UserLoginInfo(theUser.LoginProvider, theUser.ProviderKey)));

            return userLoginList;

        }

        public virtual async Task<TUser> FindAsync(UserLoginInfo login)
        {
            if (login == null) throw new ArgumentNullException("login");

            var userLogin = await _repository.WithConnectionAsync(db => db.QueryAsync<TUserLogin>
                (_repository.FindIdentityUserLogin,
                    new {provider = login.LoginProvider, key = login.ProviderKey}));
            if (userLogin == null || !userLogin.Any()) return null;

            return await _repository.WithConnectionAsync
                (db => db.Get<TUser>(userLogin.First().UserId));
        }

        public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            if(user == null || user.Id == null) throw new ArgumentNullException("user");
            var theClaim = await _repository.WithConnectionAsync
                (db => db.QueryAsync<TUserClaim>(_repository.GetClaimsAsync, new {id = user.Id}));
            var claims = new List<Claim>();
            claims.AddRange(theClaim.Select(c => new Claim(c.ClaimType, c.ClaimValue)));
            return claims;
        }

        public virtual async Task AddClaimAsync(TUser user, Claim claim)
        {
            if (user == null || user.Id == null || claim == null) throw new ArgumentNullException("claim");
            await _repository.WithConnectionAsync(db => db.InsertAsync(new TUserClaim
            {
                ClaimType = claim.Type,
                ClaimValue = claim.Value,
                UserId = user.Id
            }));
        }

        public virtual async Task RemoveClaimAsync(TUser user, Claim claim)
        {
            await _repository.WithConnectionAsync(db =>db.ExecuteAsync(_repository.RemoveClaimAsync,
                    new {id = user.Id, claimValue = claim.Value, claimType = claim.Type}));
        }

        public virtual async Task AddToRoleAsync(TUser user, string roleName)
        {
            if(user == null || user.Id == null || string.IsNullOrWhiteSpace(roleName)) throw new ArgumentNullException("user");

            var theRole = await _repository.WithConnectionAsync(db => db.Query<TRole>
                (_repository.GetRoleIdByName, new {name = roleName}).FirstOrDefault());

            if(theRole == null) throw new InvalidOperationException("Role Not Found");

            _repository.WithConnection(db =>
            {
                db.Insert(new TUserRole {UserId = user.Id, RoleId = theRole.Id});
            });
        }

        public  virtual async Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            if (user == null || user.Id == null || string.IsNullOrWhiteSpace(roleName)) throw new ArgumentNullException("user");

            var theRole = await _repository.WithConnectionAsync(db => db.Query<TRole>
                (_repository.GetRoleIdByName, new { name = roleName }).FirstOrDefault());

            if (theRole == null) throw new InvalidOperationException("Role Not Found");

            _repository.WithConnection(db => db.Execute(_repository.RemoveFromRole, new { userId = user.Id, roleId = theRole.Id }));
        }

        public virtual async Task<IList<string>> GetRolesAsync(TUser user)
        {
            return await _repository.WithConnectionAsync(db => db.Query<string>(_repository.GetRolesAsync, new {userId = user.Id}).ToList());
        }

        public virtual async Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            return await _repository.WithConnectionAsync(db =>
                            db.ExecuteScalarAsync<bool>(_repository.IsInRoleAsync, new {userId = user.Id, name = roleName}));
        }

        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            if (user == null || user.Id == null) throw new ArgumentNullException("user");
            user.PasswordHash = passwordHash;
            SetDeferUserIfDirty(user, u => _deferUser.PasswordHash = user.PasswordHash);
            return Task.FromResult(0);

            //await _repository.WithConnectionAsync(db => db.ExecuteAsync(_repository.SetPasswordHashAsync, new {hash = passwordHash, id = user.Id}));
        }

        public virtual Task<string> GetPasswordHashAsync(TUser user)
        {
            if (user == null || user.Id == null) throw new ArgumentNullException("user");
            return Task.FromResult(GetUserIfDirty(user).PasswordHash);
            //return await _repository.WithConnectionAsync(db => db.ExecuteScalarAsync<string>
            //    (_repository.GetPasswordHashAsync,new {id = user.Id}));
        }

        public virtual Task<bool> HasPasswordAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(!string.IsNullOrWhiteSpace(user.PasswordHash));
        }

        public virtual Task SetSecurityStampAsync(TUser user, string stamp)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.SecurityStamp = stamp;
            SetDeferUserIfDirty(user, u =>  _deferUser.SecurityStamp = user.SecurityStamp);

            return Task.FromResult(0);
            //await _repository.WithConnectionAsync(db => db.ExecuteAsync(
            //    _repository.SetSecurityStampAsync, new {securityStamp = stamp, id = user.Id, user}));
        }

        public virtual Task<string> GetSecurityStampAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(GetUserIfDirty(user).SecurityStamp);
        }

        public IQueryable<TUser> Users
        {
            get { return _repository.WithConnection(db => db.GetAll<TUser>().AsQueryable()); }
        }

        public virtual Task SetEmailAsync(TUser user, string email)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.Email = email;
            SetDeferUserIfDirty(user, u => _deferUser.Email = user.Email);
            return Task.FromResult(0);
        }

        public virtual Task<string> GetEmailAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(GetUserIfDirty(user).Email);
        }

        public virtual Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(GetUserIfDirty(user).EmailConfirmed);
        }

        public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.EmailConfirmed = confirmed;
            SetDeferUserIfDirty(user, u => _deferUser.EmailConfirmed = user.EmailConfirmed);
            return Task.FromResult(0);
        }

        public virtual async Task<TUser> FindByEmailAsync(string email)
        {
            return await
                _repository.WithConnectionAsync(db => db.Query<TUser>(_repository.FindUserByEmailAsync, new { mail = email }).FirstOrDefault());
        }

        public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.PhoneNumber = phoneNumber;
            SetDeferUserIfDirty(user, u => _deferUser.PhoneNumber = user.PhoneNumber);
            return Task.FromResult(0);
            //await _repository.WithConnectionAsync(db => db.ExecuteAsync(_repository.SetPhoneNumberConfirmedAsync, 
            //    new { phone = phoneNumber, id = user.Id }));
        }

        public virtual Task<string> GetPhoneNumberAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(GetUserIfDirty(user).PhoneNumber);
        }

        public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(GetUserIfDirty(user).PhoneNumberConfirmed);
        }

        public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.PhoneNumberConfirmed = confirmed;
            SetDeferUserIfDirty(user, u => _deferUser.PhoneNumberConfirmed = user.PhoneNumberConfirmed);
            return Task.FromResult(0);

            //await _repository.WithConnectionAsync(db => db.ExecuteAsync
            //    (_repository.SetPhoneNumberConfirmedAsync, new { confirm = confirmed, id = user.Id }));
        }

        public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.TwoFactorEnabled = enabled;
            SetDeferUserIfDirty(user, u => _deferUser.TwoFactorEnabled = user.TwoFactorEnabled);
            return Task.FromResult(0);

            //await _repository.WithConnectionAsync(db => db.ExecuteAsync
            //   (_repository.SetTwoFactorEnabledAsync, new { twoFactor = enabled, id = user.Id }));

        }

        public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(GetUserIfDirty(user).TwoFactorEnabled);
        }

        public virtual Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");
            
            var date = _repository.WithConnection(db => db.ExecuteScalar<DateTime?>
                (_repository.GetLockoutEndDateAsync, new {id = user.Id}));

            return Task.FromResult(date.HasValue
                    ? new DateTimeOffset(DateTime.SpecifyKind(date.Value, DateTimeKind.Utc))
                    : new DateTimeOffset());
        }

        public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            if (user == null || user.Id == null) throw new ArgumentNullException("user");
            user.LockoutEndDateUtc = lockoutEnd == DateTimeOffset.MinValue ? (DateTime?) null : lockoutEnd.UtcDateTime;
            SetDeferUserIfDirty(user, u => _deferUser.LockoutEndDateUtc = u.LockoutEndDateUtc );

            return Task.FromResult(0);
        }

        public virtual Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            if (user == null || user.Id == null) throw new ArgumentNullException("user");
            user.AccessFailedCount += 1;
            SetDeferUserIfDirty(user, u => _deferUser.AccessFailedCount = u.AccessFailedCount);
            
            return Task.FromResult(user.AccessFailedCount);
        }

        public virtual Task ResetAccessFailedCountAsync(TUser user)
        {
            if (user == null || user.Id == null) throw new ArgumentNullException("user");
            user.AccessFailedCount = 0;
            SetDeferUserIfDirty(user, u => _deferUser.AccessFailedCount = u.AccessFailedCount);
           
            return Task.FromResult(0);
        }

        public virtual async Task<int> GetAccessFailedCountAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return await Task.FromResult(GetUserIfDirty(user).AccessFailedCount);
        }

        public virtual Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(GetUserIfDirty(user).LockoutEnabled);
        }

        public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            if (user == null || user.Id == null) throw new ArgumentNullException("user");
            user.LockoutEnabled = enabled;
            SetDeferUserIfDirty(user, u => _deferUser.LockoutEnabled = u.LockoutEnabled);

            return Task.FromResult(0);
        }

        private void SetDeferUserIfDirty(TUser user, Action<TUser> action)
        {
            if (_isDirty <= 0) _deferUser = user;
            else if (!string.Equals(_deferUser.Id.ToString(), user.Id.ToString(), StringComparison.InvariantCultureIgnoreCase))
            {
                _deferUser = user;
                action.Invoke(user);
            }
            else action.Invoke(user);
            _isDirty += 1;
        }

        private TUser GetUserIfDirty(TUser user)
        {
            return _isDirty <= 0 ? user : _deferUser;
        }

        public void Dispose()
        {
            _isDirty = 0;
            _deferUser = null;
        }
    }
}