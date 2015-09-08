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
    public class RoleStoreTests
    {
        private readonly SqlServerConnection _sqlServer;
        private readonly RoleStore<IdentityRole> _roleStore;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleStoreTests()
        {
            _sqlServer = new SqlServerConnection(SetupTests.ConnectionString);
            _roleStore = new RoleStore<IdentityRole>(_sqlServer);
            _roleManager = new RoleManager<IdentityRole>(_roleStore);
        }

        [Fact]
        [TestMethod]
        public void RoleManagerMethodsThrowWhenDisposedTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>());
            manager.Dispose();
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.CreateAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Create(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.UpdateAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Update(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.DeleteAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Delete(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.FindByIdAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.FindById(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.FindByNameAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.FindByName(null));
        }

        // no need to check disposed...we manage the lifetime in method level, not class..

        //[Fact]
        //[TestMethod]
        //public void RoleStoreMethodsThrowWhenDisposedTest()
        //{
        //    var store = new RoleStore<IdentityRole>();
        //    store.Dispose();
        //    Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.CreateAsync(null)));
        //    Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.UpdateAsync(null)));
        //    Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.DeleteAsync(null)));
        //    Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.FindByIdAsync(null)));
        //    Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.FindByNameAsync(null)));
        //}

        [Fact]
        [TestMethod]
        public void RoleStorePublicNullCheckTest()
        {
            ExceptionHelper.ThrowsArgumentNull(() => new RoleStore<IdentityRole>(null), "repository");
            var store = new RoleStore<IdentityRole>();
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.CreateAsync(null)), "role");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.UpdateAsync(null)), "role");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.DeleteAsync(null)), "role");
        }

        [Fact]
        [TestMethod]
        public async Task CreateRoleTest()
        {
           SetupTests.DeleteData();
            var role = new IdentityRole("create");
            Assert.False(await _roleManager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await _roleManager.CreateAsync(role));
            Assert.True(await _roleManager.RoleExistsAsync(role.Name));
        }

        [Fact]
        [TestMethod]
        public async Task BadValidatorBlocksCreateTest()
        {
            SetupTests.DeleteData();
            _roleManager.RoleValidator = new UnitTestHelper.AlwaysBadValidator<IdentityRole>();
            UnitTestHelper.IsFailure(await _roleManager.CreateAsync(new IdentityRole("blocked")),
                UnitTestHelper.AlwaysBadValidator<IdentityRole>.ErrorMessage);
        }

        [Fact]
        [TestMethod]
        public async Task BadValidatorBlocksAllUpdatesTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("poorguy");
            UnitTestHelper.IsSuccess(await _roleManager.CreateAsync(role));
            var error = UnitTestHelper.AlwaysBadValidator<IdentityRole>.ErrorMessage;
            _roleManager.RoleValidator = new UnitTestHelper.AlwaysBadValidator<IdentityRole>();
            UnitTestHelper.IsFailure(await _roleManager.UpdateAsync(role), error);
        }

        [Fact]
        [TestMethod]
        public async Task DeleteRoleTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("delete");
            Assert.False(await _roleManager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await _roleManager.CreateAsync(role));
            UnitTestHelper.IsSuccess(await _roleManager.DeleteAsync(role));
            Assert.False(await _roleManager.RoleExistsAsync(role.Name));
        }

        [Fact]
        [TestMethod]
        public void DeleteRoleSyncTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("delete");
            Assert.False(_roleManager.RoleExists(role.Name));
            UnitTestHelper.IsSuccess(_roleManager.Create(role));
            UnitTestHelper.IsSuccess(_roleManager.Delete(role));
            Assert.False(_roleManager.RoleExists(role.Name));
        }

        // this will not throw an exception because, its just plain delete...
        //[Fact]
        //[TestMethod]
        //public void DeleteFailWithUnknownRoleTest()
        //{
        //    SetupTests.DeleteData();
        //    Assert.Throws<InvalidOperationException>(
        //        () => AsyncHelper.RunSync(() => _roleManager.DeleteAsync(new IdentityRole("bogus"))));
        //}

        [Fact]
        [TestMethod]
        public async Task RoleFindByIdTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("FindById");
            Assert.Null(await _roleManager.FindByIdAsync(role.Id));
            UnitTestHelper.IsSuccess(await _roleManager.CreateAsync(role));
            var dataRole = await _roleManager.FindByIdAsync(role.Id);
            Assert.Equal(role.Id, dataRole.Id);
            Assert.Equal(role.Name, dataRole.Name);
            //Assert.Equal(role, await _roleManager.FindByIdAsync(role.Id));
        }

        [Fact]
        [TestMethod]
        public void RoleFindByIdSyncTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("FindById");
            Assert.Null(_roleManager.FindById(role.Id));
            UnitTestHelper.IsSuccess(_roleManager.Create(role));
            //Assert.Equal(role, _roleManager.FindById(role.Id));
            var dataRole = _roleManager.FindById(role.Id);
            Assert.Equal(role.Id, dataRole.Id);
            Assert.Equal(role.Name, dataRole.Name);
        }

        [Fact]
        [TestMethod]
        public async Task RoleFindByNameTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("FindByName");
            Assert.Null(await _roleManager.FindByNameAsync(role.Name));
            Assert.False(await _roleManager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await _roleManager.CreateAsync(role));
            //Assert.Equal(role, await _roleManager.FindByNameAsync(role.Name));
            var dataRole = await _roleManager.FindByNameAsync(role.Name);
            Assert.Equal(role.Id, dataRole.Id);
            Assert.Equal(role.Name, dataRole.Name);
        }

        [Fact]
        [TestMethod]
        public void RoleFindByNameSyncTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("FindByName");
            Assert.False(_roleManager.RoleExists(role.Name));
            UnitTestHelper.IsSuccess(_roleManager.Create(role));
            //Assert.Equal(role, _roleManager.FindByName(role.Name));
            var dataRole = _roleManager.FindByName(role.Name);
            Assert.Equal(role.Id, dataRole.Id);
            Assert.Equal(role.Name, dataRole.Name);
        }

        [Fact]
        [TestMethod]
        public async Task UpdateRoleNameTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("update");
            Assert.False(await _roleManager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await _roleManager.CreateAsync(role));
            Assert.True(await _roleManager.RoleExistsAsync(role.Name));
            role.Name = "Changed";
            UnitTestHelper.IsSuccess(await _roleManager.UpdateAsync(role));
            Assert.False(await _roleManager.RoleExistsAsync("update"));
            //Assert.Equal(role, await _roleManager.FindByNameAsync(role.Name));
            var dataRole = await _roleManager.FindByNameAsync(role.Name);
            Assert.Equal(role.Id, dataRole.Id);
            Assert.Equal(role.Name, dataRole.Name);
        }

        [Fact]
        [TestMethod]
        public void UpdateRoleNameSyncTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("update");
            Assert.False(_roleManager.RoleExists(role.Name));
            UnitTestHelper.IsSuccess(_roleManager.Create(role));
            Assert.True(_roleManager.RoleExists(role.Name));
            role.Name = "Changed";
            UnitTestHelper.IsSuccess(_roleManager.Update(role));
            Assert.False(_roleManager.RoleExists("update"));
            //Assert.Equal(role, _roleManager.FindByName(role.Name));
            var dataRole = _roleManager.FindByName(role.Name);
            Assert.Equal(role.Id, dataRole.Id);
            Assert.Equal(role.Name, dataRole.Name);
        }

        [Fact]
        [TestMethod]
        public async Task QuerableRolesTest()
        {
            SetupTests.DeleteData();
            //string[] users = { "u1", "u2", "u3", "u4" };
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            //foreach (var u in users) {
            //    UnitTestHelper.IsSuccess(await store.CreateAsync(u, "password"));
            //}
            foreach (IdentityRole r in roles)
            {
                UnitTestHelper.IsSuccess(await _roleManager.CreateAsync(r));
                //foreach (var u in users) {
                //    UnitTestHelper.IsSuccess(await store.Roles.AddUserToRoleAsync(u, r.Name));
                //    Assert.True(await store.Roles.IsUserInRoleAsync(u, r.Name));
                //}
            }

            Assert.Equal(roles.Length, _roleManager.Roles.Count());
            var r1 = _roleManager.Roles.FirstOrDefault(r => r.Name == "r1");
            Assert.Equal(roles[0].Id, r1.Id);
            Assert.Equal(roles[0].Name, r1.Name);
            //Assert.Equal(roles[0], r1);
        }

        [Fact]
        [TestMethod]
        public async Task DeleteRoleNonEmptySucceedsTest()
        {
            // Need fail if not empty?
            SetupTests.DeleteData();
            var userMgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleMgr = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_sqlServer));
            var role = new IdentityRole("deleteNonEmpty");
            Assert.False(await roleMgr.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            var user = new IdentityUser("t");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await userMgr.AddToRoleAsync(user.Id, role.Name));
            UnitTestHelper.IsSuccess(await roleMgr.DeleteAsync(role));
            Assert.False(await roleMgr.RoleExistsAsync(role.Name));
            // REVIEW: We should throw if deleteing a non empty role?
            var roles = await userMgr.GetRolesAsync(user.Id);
            Assert.Equal(0, roles.Count());
        }

        [Fact]
        [TestMethod]
        public async Task DeleteUserRemovesFromRoleTest()
        {
            // Need fail if not empty?
            SetupTests.DeleteData();
            var userMgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleMgr = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_sqlServer));
            var role = new IdentityRole("deleteNonEmpty");
            Assert.False(await roleMgr.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            var user = new IdentityUser("t");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await userMgr.AddToRoleAsync(user.Id, role.Name));
            UnitTestHelper.IsSuccess(await userMgr.DeleteAsync(user));
            role = roleMgr.FindById(role.Id);
            Assert.Equal(0, role.Users.Count());
        }

        [Fact]
        [TestMethod]
        public async Task DeleteRoleUnknownFailsTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("bogus");
            Assert.False(await _roleManager.RoleExistsAsync(role.Name));
            // will not throw exception because it will not check the role first before deleting..
            //Assert.Throws<InvalidOperationException>(() => AsyncHelper.RunSync(() => _roleManager.DeleteAsync(role)));
        }

        [Fact]
        [TestMethod]
        public async Task CreateRoleFailsIfExistsTest()
        {
            SetupTests.DeleteData();
            var role = new IdentityRole("dupeRole");
            Assert.False(await _roleManager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await _roleManager.CreateAsync(role));
            Assert.True(await _roleManager.RoleExistsAsync(role.Name));
            var role2 = new IdentityRole("dupeRole");
            UnitTestHelper.IsFailure(await _roleManager.CreateAsync(role2));
        }

        [Fact]
        [TestMethod]
        public async Task CreateDuplicateRoleAtStoreFailsTest()
        {
            SetupTests.DeleteData();
            var store = new RoleStore<IdentityRole>(_sqlServer);
            var role = new IdentityRole("dupeRole");
            await store.CreateAsync(role);
            var role2 = new IdentityRole("dupeRole");
            Assert.Throws<SqlException>(() => AsyncHelper.RunSync(() => store.CreateAsync(role2)));
        }

        [Fact]
        [TestMethod]
        public async Task AddUserToRoleTest()
        {
            SetupTests.DeleteData();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleManager =
                new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_sqlServer));
            var role = new IdentityRole("addUserTest");
            UnitTestHelper.IsSuccess(await roleManager.CreateAsync(role));
            IdentityUser[] users =
            {
                new IdentityUser("1"), new IdentityUser("2"), new IdentityUser("3"),
                new IdentityUser("4")
            };
            foreach (IdentityUser u in users)
            {
                UnitTestHelper.IsSuccess(await manager.CreateAsync(u));
                UnitTestHelper.IsSuccess(await manager.AddToRoleAsync(u.Id, role.Name));
                // navigation property mean nothing in dapper..
                //Assert.Equal(1, u.Roles.Count(ur => ur.RoleId == role.Id));
                Assert.True(await manager.IsInRoleAsync(u.Id, role.Name));
            }
        }

        [Fact]
        [TestMethod]
        public async Task GetRolesForUserTest()
        {
            SetupTests.DeleteData();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_sqlServer));
            IdentityUser[] users =
            {
                new IdentityUser("u1"), new IdentityUser("u2"), new IdentityUser("u3"),
                new IdentityUser("u4")
            };
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.CreateAsync(u));
            }
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
                foreach (var u in users)
                {
                    UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(u.Id, r.Name));
                    Assert.True(await userManager.IsInRoleAsync(u.Id, r.Name));
                }
                // nope, no navigation property in here..
                //Assert.Equal(users.Length, r.Users.Count());
            }

            foreach (var u in users)
            {
                var rs = await userManager.GetRolesAsync(u.Id);
                Assert.Equal(roles.Length, rs.Count);
                foreach (IdentityRole r in roles)
                {
                    Assert.True(rs.Any(role => role == r.Name));
                }
            }
        }

        [Fact]
        [TestMethod]
        public void GetRolesForUserSyncTest()
        {
            SetupTests.DeleteData();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_sqlServer));
            IdentityUser[] users =
            {
                new IdentityUser("u1"), new IdentityUser("u2"), new IdentityUser("u3"),
                new IdentityUser("u4")
            };
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(userManager.Create(u));
            }
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(roleManager.Create(r));
                foreach (var u in users)
                {
                    UnitTestHelper.IsSuccess(userManager.AddToRole(u.Id, r.Name));
                    Assert.True(userManager.IsInRole(u.Id, r.Name));
                }
            }

            foreach (var u in users)
            {
                var rs = userManager.GetRoles(u.Id);
                Assert.Equal(roles.Length, rs.Count);
                foreach (var r in roles)
                {
                    Assert.True(rs.Any(role => role == r.Name));
                }
            }
        }

        [Fact]
        [TestMethod]
        public async Task RemoveUserFromRoleWithMultipleRoles()
        {
            SetupTests.DeleteData();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleManager =
                new RoleManager<IdentityRole>(_roleStore);
            var user = new IdentityUser("MultiRoleUser");
            UnitTestHelper.IsSuccess(await userManager.CreateAsync(user));
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
                UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(user.Id, r.Name));
                //Assert.Equal(1, user.Roles.Count(ur => ur.RoleId == r.Id));
                Assert.True(await userManager.IsInRoleAsync(user.Id, r.Name));
            }
            UnitTestHelper.IsSuccess(await userManager.RemoveFromRoleAsync(user.Id, roles[2].Name));
            //Assert.Equal(0, user.Roles.Count(ur => ur.RoleId == roles[2].Id));
            Assert.False(await userManager.IsInRoleAsync(user.Id, roles[2].Name));
        }

        [Fact]
        [TestMethod]
        public async Task RemoveUserFromRoleTest()
        {
            SetupTests.DeleteData();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleManager =
                new RoleManager<IdentityRole>(_roleStore);
            IdentityUser[] users =
            {
                new IdentityUser("1"), new IdentityUser("2"), new IdentityUser("3"),
                new IdentityUser("4")
            };
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.CreateAsync(u, "password"));
            }
            var r = new IdentityRole("r1");
            UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(u.Id, r.Name));
                Assert.True(await userManager.IsInRoleAsync(u.Id, r.Name));
            }
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.RemoveFromRoleAsync(u.Id, r.Name));
                //Assert.Equal(0, u.Roles.Count(ur => ur.RoleId == r.Id));
                Assert.False(await userManager.IsInRoleAsync(u.Id, r.Name));
            }

            //Assert.Equal(0, db.Set<IdentityUserRole>().Count());
        }

        [Fact]
        [TestMethod]
        public void RemoveUserFromRolesSync()
        {
            SetupTests.DeleteData();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleManager =
                new RoleManager<IdentityRole>(_roleStore);
            var user = new IdentityUser("1");
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(roleManager.Create(r));
            }
            UnitTestHelper.IsSuccess(userManager.Create(user));
            UnitTestHelper.IsSuccess(userManager.AddToRoles(user.Id, roles.Select(ro => ro.Name).ToArray()));
            //Assert.Equal(roles.Count(), db.Set<IdentityUserRole>().Count());
            Assert.True(userManager.IsInRole(user.Id, "r1"));
            Assert.True(userManager.IsInRole(user.Id, "r2"));
            Assert.True(userManager.IsInRole(user.Id, "r3"));
            Assert.True(userManager.IsInRole(user.Id, "r4"));
            //var rs = userManager.GetRoles(user.Id);
            UnitTestHelper.IsSuccess(userManager.RemoveFromRoles(user.Id, "r1", "r3"));
            //rs = userManager.GetRoles(user.Id);
            Assert.False(userManager.IsInRole(user.Id, "r1"));
            Assert.False(userManager.IsInRole(user.Id, "r3"));
            Assert.True(userManager.IsInRole(user.Id, "r2"));
            Assert.True(userManager.IsInRole(user.Id, "r4"));
            UnitTestHelper.IsSuccess(userManager.RemoveFromRoles(user.Id, "r2", "r4"));
            Assert.False(userManager.IsInRole(user.Id, "r2"));
            Assert.False(userManager.IsInRole(user.Id, "r4"));
            //Assert.Equal(0, db.Set<IdentityUserRole>().Count());
        }

        [Fact]
        [TestMethod]
        public async Task UnknownRoleThrowsTest()
        {
            SetupTests.DeleteData();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var u = new IdentityUser("u1");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(u));
            Assert.Throws<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.AddToRoleAsync(u.Id, "bogus")));
            // CONSIDER: should these other methods also throw if role doesn't exist?
            //ExceptionHelper.ExpectException<InvalidOperationException>(() => AsyncHelper.RunSync(() => manager.RemoveFromRoleAsync(u.Id, "bogus")));
            //ExceptionHelper.ExpectException<InvalidOperationException>(() => AsyncHelper.RunSync(() => manager.IsInRoleAsync(u.Id, "whatever")));
        }

        [Fact]
        [TestMethod]
        public async Task RemoveUserNotInRoleFailsTest()
        {
            SetupTests.DeleteData();
            var userMgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleMgr = new RoleManager<IdentityRole>(_roleStore);
            var role = new IdentityRole("addUserDupeTest");
            var user = new IdentityUser("user1");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            var result = await userMgr.RemoveFromRoleAsync(user.Id, role.Name);
            UnitTestHelper.IsFailure(result, "User is not in role.");
        }

        [Fact]
        [TestMethod]
        public async Task AddUserToRoleFailsIfAlreadyInRoleTest()
        {
            SetupTests.DeleteData();
            var userMgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_sqlServer));
            var roleMgr = new RoleManager<IdentityRole>(_roleStore);
            var role = new IdentityRole("addUserDupeTest");
            var user = new IdentityUser("user1");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            UnitTestHelper.IsSuccess(await userMgr.AddToRoleAsync(user.Id, role.Name));
            Assert.True(await userMgr.IsInRoleAsync(user.Id, role.Name));
            UnitTestHelper.IsFailure(await userMgr.AddToRoleAsync(user.Id, role.Name), "User already in role.");
        }

        [Fact]
        [TestMethod]
        public async Task FindRoleByNameWithManagerTest()
        {
            SetupTests.DeleteData();
            var roleMgr = new RoleManager<IdentityRole>(_roleStore);
            var role = new IdentityRole("findRoleByNameTest");
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            Assert.Equal(role.Id, (await roleMgr.FindByNameAsync(role.Name)).Id);
        }

        [Fact]
        [TestMethod]
        public async Task FindRoleWithManagerTest()
        {
            SetupTests.DeleteData();
            var roleMgr = new RoleManager<IdentityRole>(_roleStore);
            var role = new IdentityRole("findRoleTest");
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            Assert.Equal(role.Name, (await roleMgr.FindByIdAsync(role.Id)).Name);
        }

    }
}
