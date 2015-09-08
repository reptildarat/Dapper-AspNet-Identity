using System;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Identity.Dapper.Repository;
using AspNet.Identity.Dapper.Repository.SqlServer;
using AspNet.Identity.Dapper.SqlServer.Tests.Setup;
using Microsoft.AspNet.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xunit;
using Assert = Xunit.Assert;

namespace AspNet.Identity.Dapper.SqlServer.Tests
{
    [TestClass]
    public class IdentityUserStoreTests
    {
        private readonly SqlServerConnection _sqlServer;
        private readonly UserStore<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim> _userStore;
        private readonly UserManager<IdentityUser> _userManager;

        public IdentityUserStoreTests()
        {
            SetupTests.CreateTable();
            _sqlServer = new SqlServerConnection(SetupTests.ConnectionString);
            _userStore = new UserStore
                <IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
                (_sqlServer);

            _userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
        }

        [Fact]
        [TestMethod]
        public void AddUserWithNoUserNameFailsTest()
        {
            SetupTests.SetupDatabase();
            Assert.Throws<SqlException>(() => AsyncHelper.RunSync(() => _userStore.CreateAsync(new IdentityUser())));
        }

        [Fact]
        [TestMethod]
        public async Task AddDupeUserIdWithStoreFailsTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("dupemgmt");
            await _userStore.CreateAsync(user);
            var u2 = new IdentityUser{Id = user.Id, UserName = "User"};
            try
            {
                await _userStore.CreateAsync(u2);
                Assert.False(true);
            }
            catch (Exception e)
            {
                Assert.True(e.Message.Contains("duplicate key"));
            }
        }

        [Fact]
        [TestMethod]
        public async Task AddDupeUserNameWithStoreFailsTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("dupe");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var u2 = new IdentityUser("DUPe");
            Assert.Throws<SqlException>(() => AsyncHelper.RunSync(() => _userStore.CreateAsync(u2)));
        }

        /// <summary>
        /// Imposible to do without UserManager, because by default the email is not unique in the table.
        /// todo: make it possible, maybe add one abstraction for DbEntityValdiationException?
        /// </summary>
        /// <returns></returns>
        [Fact]
        [TestMethod]
        
        public async Task AddDupeEmailWithStoreFailsTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("u1") { Email = "email" };
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var u2 = new IdentityUser("u2") { Email = "email" };
            //Assert.Throws<SqlException>(() => AsyncHelper.RunSync(() => _userStore.CreateAsync(u2)));
        }

        [Fact]
        [TestMethod]
        public async Task DeleteUserTest()
        {
            SetupTests.SetupDatabase();
            var mgmt = new IdentityUser("deletemgmttest");
            await _userStore.CreateAsync(mgmt);
            var data = await _userStore.FindByIdAsync(mgmt.Id);
            Assert.NotNull(data);
            await _userStore.DeleteAsync(mgmt);
            Assert.Null(await _userStore.FindByIdAsync(mgmt.Id));
        }

        [Fact]
        [TestMethod]
        public async Task CreateLoadDeleteUserTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("Test");
            Assert.Null(await _userStore.FindByIdAsync(user.Id));
            await _userStore.CreateAsync(user);
            var loadUser = await _userStore.FindByIdAsync(user.Id);
            Assert.NotNull(loadUser);

            Assert.Equal(user.Id, loadUser.Id);
            await _userStore.DeleteAsync(loadUser);
            loadUser = await _userStore.FindByIdAsync(user.Id);
            Assert.Null(loadUser);
        }

        [Fact]
        [TestMethod]
        public async Task FindByUserName()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("Hao");
            await _userStore.CreateAsync(user);
            var found = await _userStore.FindByNameAsync("hao");
            Assert.NotNull(found);
            Assert.Equal(user.Id, found.Id);

            found = await _userStore.FindByNameAsync("HAO");
            Assert.NotNull(found);
            Assert.Equal(user.Id, found.Id);

            found = await _userStore.FindByNameAsync("Hao");
            Assert.NotNull(found);
            Assert.Equal(user.Id, found.Id);
        }

        [Fact]
        [TestMethod]
        public async Task GetAllUsersTest()
        {
            SetupTests.SetupDatabase();
            var users = new[]
            {
                new IdentityUser{UserName = "user1", Email = "user1"},
                new IdentityUser{UserName = "user2", Email = "user2"},
                new IdentityUser{UserName = "user3", Email = "user3"}
            };

            foreach (IdentityUser u in users)
            {
                await _userStore.CreateAsync(u);
            }

            IQueryable<IUser> usersQ = _userStore.Users;
            Assert.Equal(3, usersQ.Count());
            Assert.NotNull(usersQ.FirstOrDefault(u => u.UserName == "user1"));
            Assert.NotNull(usersQ.FirstOrDefault(u => u.UserName == "user2"));
            Assert.NotNull(usersQ.FirstOrDefault(u => u.UserName == "user3"));
            Assert.Null(usersQ.FirstOrDefault(u => u.UserName == "bogus"));
        }
    }
}
