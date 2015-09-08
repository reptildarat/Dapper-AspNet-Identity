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
    public class LoginTests
    {
        private readonly SqlServerConnection _sqlServer;
        private readonly RoleStore<IdentityRole> _roleStore;
        private readonly RoleManager<IdentityRole> _roleManager;

        public LoginTests()
        {
            _sqlServer = new SqlServerConnection(SetupTests.ConnectionString);
            _roleStore = new RoleStore<IdentityRole>(_sqlServer);
            _roleManager = new RoleManager<IdentityRole>(_roleStore);
        }

        [Fact]
        [TestMethod]
        public async Task LinkUnlinkDeletesTest()
        {
            SetupTests.DeleteData();
            var mgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var user = new IdentityUser("linkunlinktest");
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            var userLogin1 = new UserLoginInfo("provider1", "p1-1");
            var userLogin2 = new UserLoginInfo("provider2", "p2-1");
            Assert.Equal(0, (await mgr.GetLoginsAsync(user.Id)).Count);
            UnitTestHelper.IsSuccess(await mgr.AddLoginAsync(user.Id, userLogin1));
            Assert.Equal(1, user.Logins.Count(l => l.ProviderKey == "p1-1"));
            Assert.Equal(1, (await mgr.GetLoginsAsync(user.Id)).Count);
            UnitTestHelper.IsSuccess(await mgr.AddLoginAsync(user.Id, userLogin2));
            Assert.Equal(1, user.Logins.Count(l => l.ProviderKey == "p2-1"));
            Assert.Equal(2, (await mgr.GetLoginsAsync(user.Id)).Count);
            UnitTestHelper.IsSuccess(await mgr.RemoveLoginAsync(user.Id, userLogin1));
            Assert.Equal(0, user.Logins.Count(l => l.ProviderKey == "p1-1"));
            Assert.Equal(1, user.Logins.Count(l => l.ProviderKey == "p2-1"));
            Assert.Equal(1, (await mgr.GetLoginsAsync(user.Id)).Count());
            UnitTestHelper.IsSuccess(await mgr.RemoveLoginAsync(user.Id, userLogin2));
            Assert.Equal(0, (await mgr.GetLoginsAsync(user.Id)).Count);
            //Assert.Equal(0, db.Set<IdentityUserLogin>().Count());
        }

        [Fact]
        [TestMethod]
        public async Task AddDuplicateLoginFailsTest()
        {
            SetupTests.DeleteData();
            var mgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var user = new IdentityUser("dupeLogintest");
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            var userLogin1 = new UserLoginInfo("provider1", "p1-1");
            UnitTestHelper.IsSuccess(await mgr.AddLoginAsync(user.Id, userLogin1));
            UnitTestHelper.IsFailure(await mgr.AddLoginAsync(user.Id, userLogin1));
        }

        [Fact]
        [TestMethod]
        public async Task AddLoginNullLoginFailsTest()
        {
            SetupTests.DeleteData();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var user = new IdentityUser("Hao");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.AddLoginAsync(user.Id, null)),
                "login");
        }
    }
}