using System.Collections.Generic;
using System.Security.Claims;
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
    public class UserClaimTests
    {
        private readonly SqlServerConnection _sqlServer;


        public UserClaimTests()
        {
            _sqlServer = new SqlServerConnection(SetupTests.ConnectionString);
        }

        [Fact]
        [TestMethod]
        public async Task AddRemoveUserClaimTest()
        {
            SetupTests.DeleteData();
            var store = new UserStore<IdentityUser>(_sqlServer);
            
            var user = new IdentityUser("ClaimsAddRemove");
            await store.CreateAsync(user);
            Claim[] claims = { new Claim("c", "v"), new Claim("c2", "v2"), new Claim("c2", "v3") };
            foreach (Claim c in claims)
            {
                await store.AddClaimAsync(user, c);
            }
            await store.UpdateAsync(user);
            var userClaims = await store.GetClaimsAsync(user);
            Assert.Equal(3, userClaims.Count);
            await store.RemoveClaimAsync(user, claims[0]);
            Assert.Equal(3, userClaims.Count); // No effect until save changes
            userClaims = await store.GetClaimsAsync(user);
            Assert.Equal(2, userClaims.Count);
            await store.RemoveClaimAsync(user, claims[1]);
            Assert.Equal(2, userClaims.Count); // No effect until save changes
            userClaims = await store.GetClaimsAsync(user);
            Assert.Equal(1, userClaims.Count);
            await store.RemoveClaimAsync(user, claims[2]);
            Assert.Equal(1, userClaims.Count); // No effect until save changes
            userClaims = await store.GetClaimsAsync(user);
            Assert.Equal(0, userClaims.Count);
            //Assert.Equal(0, user.Claims.Count);
        }

        [Fact]
        [TestMethod]
        public async Task GetUserClaimTest()
        {
            SetupTests.DeleteData();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var user = new IdentityUser("u1");
            var result = await manager.CreateAsync(user);
            UnitTestHelper.IsSuccess(result);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
            }
            var userClaims = new List<Claim>(await manager.GetClaimsAsync(user.Id));
            Assert.Equal(3, userClaims.Count);
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
            }
        }

        [Fact]
        [TestMethod]
        public void GetUserClaimSyncTest()
        {
            SetupTests.DeleteData();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var user = new IdentityUser("u1");
            var result = manager.Create(user);
            UnitTestHelper.IsSuccess(result);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(manager.AddClaim(user.Id, c));
            }
            var userClaims = new List<Claim>(manager.GetClaims(user.Id));
            Assert.Equal(3, userClaims.Count);
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
            }
        }

        [Fact]
        [TestMethod]
        public void RemoveUserClaimSyncTest()
        {
            SetupTests.DeleteData();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var user = new IdentityUser("u1");
            var result = manager.Create(user);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(manager.AddClaim(user.Id, c));
            }

            var userClaims = new List<Claim>(manager.GetClaims(user.Id));
            Assert.Equal(3, userClaims.Count);
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
                UnitTestHelper.IsSuccess(manager.RemoveClaim(user.Id, c));
            }
            var cs = manager.GetClaims(user.Id);
            Assert.Equal(0, cs.Count);
            //Assert.Equal(0, db.Set<IdentityUserClaim>().Count());
        }

        [Fact]
        [TestMethod]
        public async Task RemoveUserClaimTest()
        {
            SetupTests.DeleteData();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var user = new IdentityUser("u1");
            var result = await manager.CreateAsync(user);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
            }

            var userClaims = new List<Claim>(await manager.GetClaimsAsync(user.Id));
            Assert.Equal(3, userClaims.Count);
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
                UnitTestHelper.IsSuccess(await manager.RemoveClaimAsync(user.Id, c));
            }
            var cs = await manager.GetClaimsAsync(user.Id);
            Assert.Equal(0, cs.Count);
            //Assert.Equal(0, db.Set<IdentityUserClaim>().Count());
        }

        [Fact]
        [TestMethod]
        public async Task DupeUserClaimTest()
        {
            SetupTests.DeleteData();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var user = new IdentityUser("u1");
            var result = await manager.CreateAsync(user);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                // Add dupes
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
            }

            var userClaims = new List<Claim>(await manager.GetClaimsAsync(user.Id));
            Assert.Equal(6, userClaims.Count);
            var currentExpected = 6;
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
                UnitTestHelper.IsSuccess(await manager.RemoveClaimAsync(user.Id, c));
                var cs = await manager.GetClaimsAsync(user.Id);
                currentExpected -= 2;
                Assert.Equal(currentExpected, cs.Count);
                //Assert.Equal(currentExpected, db.Set<IdentityUserClaim>().Count());
            }
        }
    }
}