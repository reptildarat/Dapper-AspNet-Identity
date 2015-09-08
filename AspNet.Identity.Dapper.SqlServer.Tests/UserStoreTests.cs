using System.Configuration;
using System.Linq;
using AspNet.Identity.Dapper.Repository;
using AspNet.Identity.Dapper.Repository.SqlServer;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AspNet.Identity.Dapper.SqlServer.Tests
{
    [TestClass]
    public class UserStoreTests
    {
        private UserStore<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim> _repo;

        public UserStoreTests()
        {
            var connection = ConfigurationManager.ConnectionStrings["SqlServerConnection"].ConnectionString;
            _repo = new UserStore<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
                (new SqlServerConnection(connection));
        }

        [TestMethod]
        public void FindByIdAsyncTest()
        {
            Assert.IsNotNull(_repo.FindByIdAsync("806ac64c-6606-4309-b9b6-3a86481aeefd").Result.UserName);
        }

        [TestMethod]
        public void FindByNameAsyncTest()
        {
            var data = _repo.FindByNameAsync("doniperdana@yahoo.com").Result;
            Assert.IsNotNull(data);
            Assert.IsTrue(data.Id == "806ac64c-6606-4309-b9b6-3a86481aeefd");
        }


        [TestMethod]
        public void GetLoginsAsyncTest()
        {
            var user = _repo.FindByNameAsync("doniperdana@yahoo.com").Result;
            var data = _repo.GetLoginsAsync(user).Result;
            Assert.IsNotNull(data);
            //Assert.IsTrue(data.First(). == "806ac64c-6606-4309-b9b6-3a86481aeefd");
        }

        //[TestMethod]
        //public void FindAsyncTests()
        //{
        //    var data = _repo.FindAsync("doniperdana@yahoo.com").Result;
        //    Assert.IsNotNull(data);
        //    Assert.IsTrue(data.Id == "806ac64c-6606-4309-b9b6-3a86481aeefd");
        //}
    }
}
