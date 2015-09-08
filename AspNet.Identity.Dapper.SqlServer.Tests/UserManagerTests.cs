using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Identity.Dapper.Repository;
using AspNet.Identity.Dapper.Repository.SqlServer;
using AspNet.Identity.Dapper.SqlServer.Tests.Setup;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Xunit;
using Assert = Xunit.Assert;

namespace AspNet.Identity.Dapper.SqlServer.Tests
{
    [TestClass]
    public class UserManagerTests
    {
        private readonly SqlServerConnection _sqlServer;
        private readonly UserStore<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim> _userStore;
        private readonly UserManager<IdentityUser> _userManager;

        public UserManagerTests()
        {
            SetupTests.CreateTable();
            _sqlServer = new SqlServerConnection(SetupTests.ConnectionString);
            _userStore = new UserStore
                <IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
                (_sqlServer);

            _userManager = UnitTestHelper.CreateManager(_sqlServer);
        }

        [Fact]
        [TestMethod]
        public void IdentityContextWithNullDbContextThrowsTest()
        {
            ExceptionHelper.ThrowsArgumentNull(() => new UserStore<IdentityUser>(null), "repository");
        }

        [Fact]
        [TestMethod]
        public async Task PasswordLengthSuccessValidatorTest()
        {
            var validator = new MinimumLengthValidator(1);
            var result = await validator.ValidateAsync("11");
            UnitTestHelper.IsSuccess(result);
        }

        [Fact]
        [TestMethod]
        public async Task PasswordTooShortValidatorTest()
        {
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(new IdentityUser("Hao"), "11"),
                "Passwords must be at least 6 characters.");
        }


        [Fact]
        [TestMethod]
        public async Task CustomPasswordValidatorTest()
        {
            _userManager.PasswordValidator = new UnitTestHelper.AlwaysBadValidator<string>();
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(new IdentityUser("Hao"), "password"),
                UnitTestHelper.AlwaysBadValidator<string>.ErrorMessage);
        }

        [Fact]
        [TestMethod]
        public async Task PasswordValidatorTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("passwordValidator");
            _userManager.PasswordValidator = new PasswordValidator { RequiredLength = 6, RequireNonLetterOrDigit = true };
            const string alphaError = "Passwords must have at least one non letter or digit character.";
            const string lengthError = "Passwords must be at least 6 characters.";
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(user, "ab@de"), lengthError);
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(user, "abcdef"), alphaError);
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(user, "___"), lengthError);
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, "abcd@e!ld!kajfd"));
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(user, "abcde"), lengthError + " " + alphaError);
        }

        [Fact]
        [TestMethod]
        public async Task CustomPasswordValidatorBlocksAddPasswordTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            _userManager.PasswordValidator = new UnitTestHelper.AlwaysBadValidator<String>();
            UnitTestHelper.IsFailure(await _userManager.AddPasswordAsync(user.Id, "password"),
                UnitTestHelper.AlwaysBadValidator<String>.ErrorMessage);
        }

        [Fact]
        [TestMethod]
        public async Task CustomUserNameValidatorTest()
        {
            SetupTests.SetupDatabase();
            _userManager.UserValidator = new UnitTestHelper.AlwaysBadValidator<IdentityUser>();
            var result = await _userManager.CreateAsync(new IdentityUser("Hao"));
            UnitTestHelper.IsFailure(result, UnitTestHelper.AlwaysBadValidator<IdentityUser>.ErrorMessage);
        }

        [Fact]
        [TestMethod]
        public async Task BadValidatorBlocksAllUpdatesTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("poorguy");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            const string error = UnitTestHelper.AlwaysBadValidator<IdentityUser>.ErrorMessage;
            _userManager.UserValidator = new UnitTestHelper.AlwaysBadValidator<IdentityUser>();
            _userManager.PasswordValidator = new UnitTestHelper.NoopValidator<string>();
            UnitTestHelper.IsFailure(await _userManager.AddClaimAsync(user.Id, new Claim("a", "b")), error);
            UnitTestHelper.IsFailure(await _userManager.AddLoginAsync(user.Id, new UserLoginInfo("", "")), error);
            UnitTestHelper.IsFailure(await _userManager.AddPasswordAsync(user.Id, "a"), error);
            UnitTestHelper.IsFailure(await _userManager.ChangePasswordAsync(user.Id, "a", "b"), error);
            UnitTestHelper.IsFailure(await _userManager.RemoveClaimAsync(user.Id, new Claim("a", "b")), error);
            UnitTestHelper.IsFailure(await _userManager.RemoveLoginAsync(user.Id, new UserLoginInfo("aa", "bb")), error);
            UnitTestHelper.IsFailure(await _userManager.RemovePasswordAsync(user.Id), error);
            UnitTestHelper.IsFailure(await _userManager.UpdateSecurityStampAsync(user.Id), error);
        }

        [Fact]
        [TestMethod]
        public async Task CreateLocalUserWithOnlyWhitespaceUserNameFails()
        {
            var result = await _userManager.CreateAsync(new IdentityUser { UserName = " " }, "password");
            UnitTestHelper.IsFailure(result, "Name cannot be null or empty.");
        }

        [Fact]
        [TestMethod]
        public async Task CreateLocalUserWithInvalidUserNameFails()
        {
            var result = await _userManager.CreateAsync(new IdentityUser { UserName = "a\0b" }, "password");
            UnitTestHelper.IsFailure(result, "User name a\0b is invalid, can only contain letters or digits.");
        }

        [Fact]
        [TestMethod]
        public async Task CreateLocalUserWithInvalidPasswordThrows()
        {
            //SetupTests.SetupDatabase();
            var result = await _userManager.CreateAsync(new IdentityUser("Hao"), "aa");
            UnitTestHelper.IsFailure(result, "Passwords must be at least 6 characters.");
        }

        [Fact]
        [TestMethod]
        public async Task CreateExternalUserWithNullFails()
        {
            //SetupTests.SetupDatabase();
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(new IdentityUser { UserName = null }),
                "Name cannot be null or empty.");
        }

        [Fact]
        [TestMethod]
        public async Task AddPasswordWhenPasswordSetFails()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("HasPassword");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, "password"));

            UnitTestHelper.IsFailure(await _userManager.AddPasswordAsync(user.Id, "User already has a password."));
        }

        [Fact]
        [TestMethod]
        public async Task FindNullIdTest()
        {
            SetupTests.SetupDatabase();
            var theTest = await _userManager.FindByIdAsync(null);
            Assert.Null(theTest);
        }

        [Fact]
        [TestMethod]
        public async Task CreateLocalUserTest()
        {
            SetupTests.SetupDatabase();
            const string password = "password";
            var theResult = await _userManager.CreateAsync(new IdentityUser("CreateLocalUserTest"), password);
            UnitTestHelper.IsSuccess(theResult);
            var user = await _userManager.FindByNameAsync("CreateLocalUserTest");
            Assert.NotNull(user);
            Assert.NotNull(user.PasswordHash);
            Assert.True(await _userManager.HasPasswordAsync(user.Id));
            var logins = await _userManager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count);
        }

        [Fact]
        [TestMethod]
        public void CreateLocalUserTestSync()
        {
            SetupTests.SetupDatabase();
            const string password = "password";
            UnitTestHelper.IsSuccess(_userManager.Create(new IdentityUser("CreateLocalUserTest"), password));
            var user = _userManager.FindByName("CreateLocalUserTest");
            Assert.NotNull(user);
            Assert.NotNull(user.PasswordHash);
            Assert.True(_userManager.HasPassword(user.Id));
            var logins = _userManager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count);
        }

        [Fact]
        [TestMethod]
        public async Task DeleteUserTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("Delete");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await _userManager.DeleteAsync(user));
            Assert.Null(await _userManager.FindByIdAsync(user.Id));
        }

        [Fact]
        [TestMethod]
        public void DeleteUserSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("Delete");
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            UnitTestHelper.IsSuccess(_userManager.Delete(user));
            Assert.Null(_userManager.FindById(user.Id));
        }


        [Fact]
        [TestMethod]
        public async Task CreateUserAddLoginTest()
        {
            SetupTests.SetupDatabase();
            const string userName = "CreateExternalUserTest";
            const string provider = "ZzAuth";
            const string providerKey = "HaoKey";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(new IdentityUser(userName)));
            var user = await _userManager.FindByNameAsync(userName);
            var login = new UserLoginInfo(provider, providerKey);
            UnitTestHelper.IsSuccess(await _userManager.AddLoginAsync(user.Id, login));
            var logins = await _userManager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count);
            Assert.Equal(provider, logins.First().LoginProvider);
            Assert.Equal(providerKey, logins.First().ProviderKey);
        }

        [Fact]
        [TestMethod]
        public void CreateUserAddLoginSyncTest()
        {
            SetupTests.SetupDatabase();
            const string userName = "CreateExternalUserTest";
            const string provider = "ZzAuth";
            const string providerKey = "HaoKey";
            UnitTestHelper.IsSuccess(_userManager.Create(new IdentityUser(userName)));
            var user = _userManager.FindByName(userName);
            var login = new UserLoginInfo(provider, providerKey);
            UnitTestHelper.IsSuccess(_userManager.AddLogin(user.Id, login));
            var logins = _userManager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(provider, logins.First().LoginProvider);
            Assert.Equal(providerKey, logins.First().ProviderKey);
        }

        [Fact]
        [TestMethod]
        // todo: cannot figure it out why the assert equal is not working
        public async Task CreateUserLoginAndAddPasswordTest()
        {
            SetupTests.SetupDatabase();
            var login = new UserLoginInfo("Provider", "key");
            var user = new IdentityUser("CreateUserLoginAddPasswordTest");
            
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await _userManager.AddLoginAsync(user.Id, login));
            UnitTestHelper.IsSuccess(await _userManager.AddPasswordAsync(user.Id, "password"));
            var logins = await _userManager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            var data = await _userManager.FindAsync(login);
            Assert.Equal(user.Id, data.Id);
            Assert.Equal(user.PasswordHash, data.PasswordHash);
            //Assert.Equal(user, await _userManager.FindAsync(login));
            var dataWithPassword = await _userManager.FindAsync(user.UserName, "password");
            Assert.Equal(user.Id, dataWithPassword.Id);
            Assert.Equal(user.PasswordHash, dataWithPassword.PasswordHash);

            //Assert.Equal(user, await _userManager.FindAsync(user.UserName, "password"));
            Assert.True(await _userManager.CheckPasswordAsync(user, "password"));
        }

        [Fact]
        [TestMethod]
        // todo: and here too, cannot figure it out why the assert equal is not working
        public void CreateUserLoginAndAddPasswordSyncTest()
        {
            SetupTests.SetupDatabase();
            var login = new UserLoginInfo("Provider", "key");
            var user = new IdentityUser("CreateUserLoginAddPasswordTest");
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            UnitTestHelper.IsSuccess(_userManager.AddLogin(user.Id, login));
            UnitTestHelper.IsSuccess(_userManager.AddPassword(user.Id, "password"));
            var logins = _userManager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            var data = _userManager.Find(login);
            Assert.Equal(user.Id, data.Id);
            Assert.Equal(user.PasswordHash, data.PasswordHash);
            //Assert.Equal(user, _userManager.Find(login));
            var dataWithPassword = _userManager.Find(user.UserName, "password");
            Assert.Equal(user.Id, dataWithPassword.Id);
            Assert.Equal(user.PasswordHash, dataWithPassword.PasswordHash);
            //Assert.Equal(user, _userManager.Find(user.UserName, "password"));
            Assert.True(_userManager.CheckPassword(user, "password"));
        }

        [Fact]
        [TestMethod]
        public async Task CreateUserAddRemoveLoginTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("CreateUserAddRemoveLoginTest");
            var login = new UserLoginInfo("Provider", "key");
            const string password = "password";
            var result = await _userManager.CreateAsync(user, password);
            Assert.NotNull(user);
            UnitTestHelper.IsSuccess(result);
            UnitTestHelper.IsSuccess(await _userManager.AddLoginAsync(user.Id, login));
            //Assert.Equal(user, await _userManager.FindAsync(login));
            var logins = await _userManager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(login.LoginProvider, logins.Last().LoginProvider);
            Assert.Equal(login.ProviderKey, logins.Last().ProviderKey);
            var stamp = await _userManager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsSuccess(await _userManager.RemoveLoginAsync(user.Id, login));
            Assert.Null(await _userManager.FindAsync(login));
            logins = await _userManager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count());
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public void CreateUserAddRemoveLoginSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("CreateUserAddRemoveLoginTest");
            var login = new UserLoginInfo("Provider", "key");
            const string password = "password";
            var result = _userManager.Create(user, password);
            Assert.NotNull(user);
            UnitTestHelper.IsSuccess(result);
            UnitTestHelper.IsSuccess(_userManager.AddLogin(user.Id, login));
            //Assert.Equal(user, _userManager.Find(login));
            var logins = _userManager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(login.LoginProvider, logins.Last().LoginProvider);
            Assert.Equal(login.ProviderKey, logins.Last().ProviderKey);
            var stamp = _userManager.GetSecurityStamp(user.Id);
            UnitTestHelper.IsSuccess(_userManager.RemoveLogin(user.Id, login));
            Assert.Null(_userManager.Find(login));
            logins = _userManager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count());
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task RemovePasswordTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("RemovePasswordTest");
            const string password = "password";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var stamp = await _userManager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsSuccess(await _userManager.RemovePasswordAsync(user.Id));
            var u = await _userManager.FindByNameAsync(user.UserName);
            Assert.NotNull(u);
            Assert.Null(u.PasswordHash);
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public void RemovePasswordSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("RemovePasswordTest");
            const string password = "password";
            UnitTestHelper.IsSuccess(_userManager.Create(user, password));
            var stamp = _userManager.GetSecurityStamp(user.Id);
            UnitTestHelper.IsSuccess(_userManager.RemovePassword(user.Id));
            var u = _userManager.FindByName(user.UserName);
            Assert.NotNull(u);
            Assert.Null(u.PasswordHash);
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task ChangePasswordTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ChangePasswordTest");
            const string password = "password";
            const string newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(await _userManager.ChangePasswordAsync(user.Id, password, newPassword));
            Assert.Null(await _userManager.FindAsync(user.UserName, password));
            //Assert.Equal(user, await _userManager.FindAsync(user.UserName, newPassword));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public void ChangePasswordSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ChangePasswordTest");
            const string password = "password";
            const string newPassword = "newpassword";
            UnitTestHelper.IsSuccess(_userManager.Create(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(_userManager.ChangePassword(user.Id, password, newPassword));
            Assert.Null(_userManager.Find(user.UserName, password));
            //Assert.Equal(user, _userManager.Find(user.UserName, newPassword));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task ResetPasswordTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ResetPasswordTest");
            const string password = "password";
            const string newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GeneratePasswordResetTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await _userManager.ResetPasswordAsync(user.Id, token, newPassword));
            Assert.Null(await _userManager.FindAsync(user.UserName, password));
            //Assert.Equal(user, await _userManager.FindAsync(user.UserName, newPassword));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task ResetPasswordWithNoStampTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ResetPasswordTest");
            const string password = "password";
            const string newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var token = await _userManager.GeneratePasswordResetTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await _userManager.ResetPasswordAsync(user.Id, token, newPassword));
            Assert.Null(await _userManager.FindAsync(user.UserName, password));
            //Assert.Equal(user, await _userManager.FindAsync(user.UserName, newPassword));
        }

        [Fact]
        [TestMethod]
        public async Task GenerateUserTokenTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("UserTokenTest");
            var user2 = new IdentityUser("UserTokenTest2");
            user2.Email = "Test@test.com";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user2));
            var token = await _userManager.GenerateUserTokenAsync("test", user.Id);
            Assert.True(await _userManager.VerifyUserTokenAsync(user.Id, "test", token));
            Assert.False(await _userManager.VerifyUserTokenAsync(user.Id, "test2", token));
            Assert.False(await _userManager.VerifyUserTokenAsync(user.Id, "test", token + "a"));
            Assert.False(await _userManager.VerifyUserTokenAsync(user2.Id, "test", token));
        }

        [Fact]
        [TestMethod]
        public void GenerateUserTokenSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("UserTokenTest");
            var user2 = new IdentityUser("UserTokenTest2");
            user2.Email = "Test@test.com";
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            UnitTestHelper.IsSuccess(_userManager.Create(user2));
            var token = _userManager.GenerateUserToken("test", user.Id);
            Assert.True(_userManager.VerifyUserToken(user.Id, "test", token));
            Assert.False(_userManager.VerifyUserToken(user.Id, "test2", token));
            Assert.False(_userManager.VerifyUserToken(user.Id, "test", token + "a"));
            Assert.False(_userManager.VerifyUserToken(user2.Id, "test", token));
        }

        [Fact]
        [TestMethod]
        public async Task GetTwoFactorEnabledTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("TwoFactorEnabledTest");
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            Assert.False(await _userManager.GetTwoFactorEnabledAsync(user.Id));
            UnitTestHelper.IsSuccess(await _userManager.SetTwoFactorEnabledAsync(user.Id, true));
            Assert.True(await _userManager.GetTwoFactorEnabledAsync(user.Id));
            UnitTestHelper.IsSuccess(await _userManager.SetTwoFactorEnabledAsync(user.Id, false));
            Assert.False(await _userManager.GetTwoFactorEnabledAsync(user.Id));
        }

        [Fact]
        [TestMethod]
        public void GetTwoFactorEnabledSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("TwoFactorEnabledTest");
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            Assert.False(_userManager.GetTwoFactorEnabled(user.Id));
            UnitTestHelper.IsSuccess(_userManager.SetTwoFactorEnabled(user.Id, true));
            Assert.True(_userManager.GetTwoFactorEnabled(user.Id));
            UnitTestHelper.IsSuccess(_userManager.SetTwoFactorEnabled(user.Id, false));
            Assert.False(_userManager.GetTwoFactorEnabled(user.Id));
        }

        [Fact]
        [TestMethod]
        public async Task ResetPasswordWithConfirmTokenFailsTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsFailure(await _userManager.ResetPasswordAsync(user.Id, token, newPassword));
            Assert.Null(await _userManager.FindAsync(user.UserName, newPassword));
            //Assert.Equal(user, await _userManager.FindAsync(user.UserName, password));
            Assert.Equal(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task ResetPasswordWithExpiredTokenFailsTest()
        {
            SetupTests.SetupDatabase();
            var provider = new DpapiDataProtectionProvider();
            //manager.PasswordResetTokens = new DataProtectorTokenProvider<IdentityUser>(provider.Create("ResetPassword")) { TokenLifespan = TimeSpan.FromTicks(0) };
            _userManager.UserTokenProvider = new DataProtectorTokenProvider<IdentityUser>(provider.Create("ResetPassword"))
            {
                TokenLifespan = TimeSpan.FromTicks(0)
            };
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GeneratePasswordResetTokenAsync(user.Id);
            Assert.NotNull(token);
            Thread.Sleep(10);
            UnitTestHelper.IsFailure(await _userManager.ResetPasswordAsync(user.Id, token, newPassword));
            Assert.Null(await _userManager.FindAsync(user.UserName, newPassword));
            //Assert.Equal(user, await _userManager.FindAsync(user.UserName, password));
            Assert.Equal(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public void ResetPasswordSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(_userManager.Create(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = _userManager.GeneratePasswordResetToken(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(_userManager.ResetPassword(user.Id, token, newPassword));
            Assert.Null(_userManager.Find(user.UserName, password));
            //Assert.Equal(user, _userManager.Find(user.UserName, newPassword));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task ResetPasswordFailsWithWrongTokenTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsFailure(await _userManager.ResetPasswordAsync(user.Id, "bogus", newPassword), "Invalid token.");
            Assert.Null(await _userManager.FindAsync(user.UserName, newPassword));
            //Assert.Equal(user, await _userManager.FindAsync(user.UserName, password));
            Assert.Equal(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task ResetPasswordFailsAfterPasswordChangeTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = _userManager.GeneratePasswordResetToken(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await _userManager.ChangePasswordAsync(user.Id, password, "bogus1"));
            UnitTestHelper.IsFailure(await _userManager.ResetPasswordAsync(user.Id, token, newPassword), "Invalid token.");
            Assert.Null(await _userManager.FindAsync(user.UserName, newPassword));
            //Assert.Equal(user, await _userManager.FindAsync(user.UserName, "bogus1"));
        }

        [Fact]
        [TestMethod]
        public async Task AddRemoveUserClaimTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ClaimsAddRemove");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            Claim[] claims = { new Claim("c", "v"), new Claim("c2", "v2"), new Claim("c2", "v3") };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(await _userManager.AddClaimAsync(user.Id, c));
            }
            var userClaims = await _userManager.GetClaimsAsync(user.Id);
            Assert.Equal(3, userClaims.Count);
            UnitTestHelper.IsSuccess(await _userManager.RemoveClaimAsync(user.Id, claims[0]));
            userClaims = await _userManager.GetClaimsAsync(user.Id);
            Assert.Equal(2, userClaims.Count);
            UnitTestHelper.IsSuccess(await _userManager.RemoveClaimAsync(user.Id, claims[1]));
            userClaims = await _userManager.GetClaimsAsync(user.Id);
            Assert.Equal(1, userClaims.Count);
            UnitTestHelper.IsSuccess(await _userManager.RemoveClaimAsync(user.Id, claims[2]));
            userClaims = await _userManager.GetClaimsAsync(user.Id);
            Assert.Equal(0, userClaims.Count);
        }

        [Fact]
        [TestMethod]
        public void AddRemoveUserClaimSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("ClaimsAddRemove");
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            Claim[] claims = { new Claim("c", "v"), new Claim("c2", "v2"), new Claim("c2", "v3") };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(_userManager.AddClaim(user.Id, c));
            }
            var userClaims = _userManager.GetClaims(user.Id);
            Assert.Equal(3, userClaims.Count);
            UnitTestHelper.IsSuccess(_userManager.RemoveClaim(user.Id, claims[0]));
            userClaims = _userManager.GetClaims(user.Id);
            Assert.Equal(2, userClaims.Count);
            UnitTestHelper.IsSuccess(_userManager.RemoveClaim(user.Id, claims[1]));
            userClaims = _userManager.GetClaims(user.Id);
            Assert.Equal(1, userClaims.Count);
            UnitTestHelper.IsSuccess(_userManager.RemoveClaim(user.Id, claims[2]));
            userClaims = _userManager.GetClaims(user.Id);
            Assert.Equal(0, userClaims.Count);
        }

        [Fact]
        [TestMethod]
        public async Task ChangePasswordFallsIfPasswordTooShortTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("user");
            var password = "password";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var result = await _userManager.ChangePasswordAsync(user.Id, password, "n");
            UnitTestHelper.IsFailure(result, "Passwords must be at least 6 characters.");
        }

        [Fact]
        [TestMethod]
        public async Task ChangePasswordFallsIfPasswordWrongTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("user");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, "password"));
            var result = await _userManager.ChangePasswordAsync(user.Id, "bogus", "newpassword");
            UnitTestHelper.IsFailure(result, "Incorrect password.");
        }

        [Fact]
        [TestMethod]
        public void ChangePasswordFallsIfPasswordWrongSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("user");
            UnitTestHelper.IsSuccess(_userManager.Create(user, "password"));
            var result = _userManager.ChangePassword(user.Id, "bogus", "newpassword");
            UnitTestHelper.IsFailure(result, "Incorrect password.");
        }

        [Fact]
        [TestMethod]
        public async Task CanRelaxUserNameAndPasswordValidationTest()
        {
            SetupTests.SetupDatabase();
            _userManager.UserValidator = new UserValidator<IdentityUser>(_userManager) { AllowOnlyAlphanumericUserNames = false };
            _userManager.PasswordValidator = new MinimumLengthValidator(1);
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(new IdentityUser("Some spaces"), "pwd"));
        }

        [Fact]
        [TestMethod]
        public async Task CanUseEmailAsUserNameTest()
        {
            SetupTests.SetupDatabase();
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(new IdentityUser("test_email@foo.com")));
        }

        [Fact]
        [TestMethod]
        public async Task AddDupeUserFailsTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("dupe");
            var user2 = new IdentityUser("dupe");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(user2), "Name dupe is already taken.");
        }

        [Fact]
        [TestMethod]
        public async Task FindWithPasswordUnknownUserReturnsNullTest()
        {
            SetupTests.SetupDatabase();
            Assert.Null(await _userManager.FindAsync("bogus", "sdlkfsadf"));
            Assert.Null(_userManager.Find("bogus", "sdlkfsadf"));
        }


        [Fact]
        [TestMethod]
        public async Task UpdateSecurityStampTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("stampMe");
            Assert.Null(user.SecurityStamp);
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(await _userManager.UpdateSecurityStampAsync(user.Id));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public void UpdateSecurityStampSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("stampMe");
            Assert.Null(user.SecurityStamp);
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(_userManager.UpdateSecurityStamp(user.Id));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task AddDupeLoginFailsTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("DupeLogin");
            var login = new UserLoginInfo("provder", "key");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await _userManager.AddLoginAsync(user.Id, login));
            var result = await _userManager.AddLoginAsync(user.Id, login);
            UnitTestHelper.IsFailure(result, "A user with that external login already exists.");
        }

        [Fact]
        [TestMethod]
        public async Task AddLoginDoesNotChangeStampTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("stampTest");
            var login = new UserLoginInfo("provder", "key");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = await _userManager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsSuccess(await _userManager.AddLoginAsync(user.Id, login));
            Assert.Equal(stamp, await _userManager.GetSecurityStampAsync(user.Id));
        }

        [Fact]
        [TestMethod]
        public async Task MixManagerAndEfTest()
        {
            SetupTests.SetupDatabase();
            var db = new UserStore<IdentityUser>(_sqlServer);
            var manager = new UserManager<IdentityUser>(db);
            var user = new IdentityUser("MixEFManagerTest");
            var password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            user.SecurityStamp = "bogus";
            UnitTestHelper.IsSuccess(await manager.UpdateAsync(user));
            var theId = await db.FindByIdAsync(user.Id);
            Assert.Equal("bogus", theId.SecurityStamp);
            //var login = new UserLoginInfo("login", "key");
            //user.Logins.Add(new IdentityUserLogin() { User = user, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });
            //UnitTestHelper.IsSuccess(manager.Update(user));
            //Assert.Equal(login.LoginProvider, db.Users.Find(user.Id).Logins.First().LoginProvider);
            //Assert.Equal(login.ProviderKey, db.Users.Find(user.Id).Logins.First().ProviderKey);
        }

        [Fact]
        [TestMethod]
        public async Task CreateUserBasicStoreTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new IdentityUser("test")));
        }

        [Fact]
        [TestMethod]
        public async Task GetAllUsersTest()
        {
            SetupTests.SetupDatabase();
            var users = new[]
            {
                new IdentityUser("user1"),
                new IdentityUser("user2"),
                new IdentityUser("user3")
            };
            foreach (IdentityUser u in users)
            {
                UnitTestHelper.IsSuccess(await _userManager.CreateAsync(u));
            }

            IQueryable<IUser> usersQ = _userManager.Users;
            Assert.Equal(3, usersQ.Count());
            Assert.NotNull(usersQ.FirstOrDefault(u => u.UserName == "user1"));
            Assert.NotNull(usersQ.FirstOrDefault(u => u.UserName == "user2"));
            Assert.NotNull(usersQ.FirstOrDefault(u => u.UserName == "user3"));
            Assert.Null(usersQ.FirstOrDefault(u => u.UserName == "bogus"));
        }

        [Fact]
        [TestMethod]
        public async Task ConfirmEmailFalseByDefaultTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            Assert.False(await _userManager.IsEmailConfirmedAsync(user.Id));
        }

        [Fact]
        [TestMethod]
        public async Task ConfirmEmailTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("test");
            Assert.False(user.EmailConfirmed);
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await _userManager.ConfirmEmailAsync(user.Id, token));
            Assert.True(await _userManager.IsEmailConfirmedAsync(user.Id));
            UnitTestHelper.IsSuccess(await _userManager.SetEmailAsync(user.Id, null));
            Assert.False(await _userManager.IsEmailConfirmedAsync(user.Id));
        }

        [Fact]
        [TestMethod]
        public void ConfirmEmailSyncTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("test");
            Assert.False(user.EmailConfirmed);
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            var token = _userManager.GenerateEmailConfirmationToken(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(_userManager.ConfirmEmail(user.Id, token));
            Assert.True(_userManager.IsEmailConfirmed(user.Id));
            UnitTestHelper.IsSuccess(_userManager.SetEmail(user.Id, null));
            Assert.False(_userManager.IsEmailConfirmed(user.Id));
        }

        [Fact]
        [TestMethod]
        public async Task ConfirmTokenFailsAfterPasswordChangeTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("test");
            Assert.False(user.EmailConfirmed);
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, "password"));
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await _userManager.ChangePasswordAsync(user.Id, "password", "newpassword"));
            UnitTestHelper.IsFailure(await _userManager.ConfirmEmailAsync(user.Id, token), "Invalid token.");
            Assert.False(await _userManager.IsEmailConfirmedAsync(user.Id));
        }

        [Fact]
        [TestMethod]
        public async Task FindByEmailTest()
        {
            SetupTests.SetupDatabase();
            const string userName = "EmailTest";
            const string email = "email@test.com";
            var user = new IdentityUser(userName) { Email = email };
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var fetch = await _userManager.FindByEmailAsync(email);
            //Assert.Equal(user, fetch);
            Assert.Equal(user.Email, fetch.Email);
            Assert.Equal(user.UserName, fetch.UserName);
        }

        [Fact]
        [TestMethod]
        public void FindByEmailSyncTest()
        {
            SetupTests.SetupDatabase();
            var userName = "EmailTest";
            var email = "email@test.com";
            var user = new IdentityUser(userName) { Email = email };
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            var fetch = _userManager.FindByEmail(email);
            //Assert.Equal(user, fetch);
            Assert.Equal(user.Email, fetch.Email);
            Assert.Equal(user.UserName, fetch.UserName);
        }

        [Fact]
        [TestMethod]
        public async Task SetEmailTest()
        {
            SetupTests.SetupDatabase();
            var userName = "EmailTest";
            var email = "email@test.com";
            var user = new IdentityUser(userName);
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            Assert.Null(await _userManager.FindByEmailAsync(email));
            var stamp = await _userManager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsSuccess(await _userManager.SetEmailAsync(user.Id, email));
            //var fetch = await _userManager.FindByEmailAsync(email);
            //Assert.Equal(user, fetch);
            Assert.Equal(email, await _userManager.GetEmailAsync(user.Id));
            Assert.False(await _userManager.IsEmailConfirmedAsync(user.Id));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task CreateDupeEmailFailsTest()
        {
            SetupTests.SetupDatabase();
            _userManager.UserValidator = new UserValidator<IdentityUser>(_userManager) { RequireUniqueEmail = true };
            var userName = "EmailTest";
            var email = "email@test.com";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(new IdentityUser(userName) { Email = email }));
            var user = new IdentityUser("two") { Email = email };
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(user), "Email 'email@test.com' is already taken.");
        }

        [Fact]
        [TestMethod]
        public async Task SetEmailToDupeFailsTest()
        {
            SetupTests.SetupDatabase();
            _userManager.UserValidator = new UserValidator<IdentityUser>(_userManager) { RequireUniqueEmail = true };
            var email = "email@test.com";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(new IdentityUser("emailtest") { Email = email }));
            var user = new IdentityUser("two") { Email = "something@else.com" };
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            UnitTestHelper.IsFailure(await _userManager.SetEmailAsync(user.Id, email),
                "Email 'email@test.com' is already taken.");
        }

        [Fact]
        [TestMethod]
        public async Task RequireUniqueEmailBlocksBasicCreateTest()
        {
            SetupTests.SetupDatabase();
            _userManager.UserValidator = new UserValidator<IdentityUser>(_userManager) { RequireUniqueEmail = true };
            UnitTestHelper.IsFailure(await _userManager.CreateAsync(new IdentityUser("emailtest"), "Email is too short."));
        }

        [Fact]
        [TestMethod]
        public async Task SetPhoneNumberTest()
        {
            SetupTests.SetupDatabase();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = await _userManager.GetSecurityStampAsync(user.Id);
            Assert.Equal(await _userManager.GetPhoneNumberAsync(user.Id), "123-456-7890");
            UnitTestHelper.IsSuccess(await _userManager.SetPhoneNumberAsync(user.Id, "111-111-1111"));
            Assert.Equal(await _userManager.GetPhoneNumberAsync(user.Id), "111-111-1111");
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public void SetPhoneNumberSyncTest()
        {
            SetupTests.SetupDatabase();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            var stamp = _userManager.GetSecurityStamp(user.Id);
            Assert.Equal(_userManager.GetPhoneNumber(user.Id), "123-456-7890");
            UnitTestHelper.IsSuccess(_userManager.SetPhoneNumber(user.Id, "111-111-1111"));
            Assert.Equal(_userManager.GetPhoneNumber(user.Id), "111-111-1111");
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task ChangePhoneNumberTest()
        {
            SetupTests.SetupDatabase();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            Assert.False(await _userManager.IsPhoneNumberConfirmedAsync(user.Id));
            var stamp = await _userManager.GetSecurityStampAsync(user.Id);
            var token1 = await _userManager.GenerateChangePhoneNumberTokenAsync(user.Id, "111-111-1111");
            UnitTestHelper.IsSuccess(await _userManager.ChangePhoneNumberAsync(user.Id, "111-111-1111", token1));
            Assert.True(await _userManager.IsPhoneNumberConfirmedAsync(user.Id));
            Assert.Equal(await _userManager.GetPhoneNumberAsync(user.Id), "111-111-1111");
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public void ChangePhoneNumberSyncTest()
        {
            SetupTests.SetupDatabase();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            var stamp = _userManager.GetSecurityStamp(user.Id);
            Assert.False(_userManager.IsPhoneNumberConfirmed(user.Id));
            var token1 = _userManager.GenerateChangePhoneNumberToken(user.Id, "111-111-1111");
            UnitTestHelper.IsSuccess(_userManager.ChangePhoneNumber(user.Id, "111-111-1111", token1));
            Assert.True(_userManager.IsPhoneNumberConfirmed(user.Id));
            Assert.Equal(_userManager.GetPhoneNumber(user.Id), "111-111-1111");
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task ChangePhoneNumberFailsWithWrongTokenTest()
        {
            SetupTests.SetupDatabase();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            Assert.False(await _userManager.IsPhoneNumberConfirmedAsync(user.Id));
            var stamp = await _userManager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsFailure(await _userManager.ChangePhoneNumberAsync(user.Id, "111-111-1111", "bogus"),
                "Invalid token.");
            Assert.False(await _userManager.IsPhoneNumberConfirmedAsync(user.Id));
            Assert.Equal(await _userManager.GetPhoneNumberAsync(user.Id), "123-456-7890");
            Assert.Equal(stamp, user.SecurityStamp);
        }

        [Fact]
        [TestMethod]
        public async Task VerifyPhoneNumberTest()
        {
            SetupTests.SetupDatabase();
            var userName = "VerifyPhoneTest";
            var user = new IdentityUser(userName);
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var num1 = "111-123-4567";
            var num2 = "111-111-1111";
            var token1 = await _userManager.GenerateChangePhoneNumberTokenAsync(user.Id, num1);
            var token2 = await _userManager.GenerateChangePhoneNumberTokenAsync(user.Id, num2);
            Assert.NotEqual(token1, token2);
            Assert.True(await _userManager.VerifyChangePhoneNumberTokenAsync(user.Id, token1, num1));
            Assert.True(await _userManager.VerifyChangePhoneNumberTokenAsync(user.Id, token2, num2));
            Assert.False(await _userManager.VerifyChangePhoneNumberTokenAsync(user.Id, token2, num1));
            Assert.False(await _userManager.VerifyChangePhoneNumberTokenAsync(user.Id, token1, num2));
        }

        [Fact]
        [TestMethod]
        public void VerifyPhoneNumberSyncTest()
        {
            SetupTests.SetupDatabase();
            const string userName = "VerifyPhoneTest";
            var user = new IdentityUser(userName);
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            const string num1 = "111-123-4567";
            const string num2 = "111-111-1111";
            Assert.False(_userManager.IsPhoneNumberConfirmed(user.Id));
            var token1 = _userManager.GenerateChangePhoneNumberToken(user.Id, num1);
            var token2 = _userManager.GenerateChangePhoneNumberToken(user.Id, num2);
            Assert.NotEqual(token1, token2);
            Assert.True(_userManager.VerifyChangePhoneNumberToken(user.Id, token1, num1));
            Assert.True(_userManager.VerifyChangePhoneNumberToken(user.Id, token2, num2));
            Assert.False(_userManager.VerifyChangePhoneNumberToken(user.Id, token2, num1));
            Assert.False(_userManager.VerifyChangePhoneNumberToken(user.Id, token1, num2));
        }

        [Fact]
        [TestMethod]
        public async Task EmailTokenFactorTest()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.EmailService = messageService;
            const string factorId = "EmailCode";
            _userManager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            const string password = "password";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(await _userManager.NotifyTwoFactorTokenAsync(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal(String.Empty, messageService.Message.Subject);
            Assert.Equal(token, messageService.Message.Body);
            Assert.True(await _userManager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public async Task EmailTokenFactorWithFormatTest()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.EmailService = messageService;
            const string factorId = "EmailCode";
            _userManager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your code is: {0}"
            });
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            const string password = "password";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(await _userManager.NotifyTwoFactorTokenAsync(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal("Security Code", messageService.Message.Subject);
            Assert.Equal("Your code is: " + token, messageService.Message.Body);
            Assert.True(await _userManager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public void EmailTokenFactorWithFormatSyncTest()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.EmailService = messageService;
            const string factorId = "EmailCode";
            _userManager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your code is: {0}"
            });
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            const string password = "password";
            UnitTestHelper.IsSuccess(_userManager.Create(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = _userManager.GenerateTwoFactorToken(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(_userManager.NotifyTwoFactorToken(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal("Security Code", messageService.Message.Subject);
            Assert.Equal("Your code is: " + token, messageService.Message.Body);
            Assert.True(_userManager.VerifyTwoFactorToken(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public async Task EmailFactorFailsAfterSecurityStampChangeTest()
        {
            SetupTests.SetupDatabase();
            const string factorId = "EmailCode";
            _userManager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await _userManager.UpdateSecurityStampAsync(user.Id));
            Assert.False(await _userManager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public void EmailTokenFactorSyncTest()
        {
            SetupTests.SetupDatabase();
            const string factorId = "EmailCode";
            _userManager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            const string password = "password";
            UnitTestHelper.IsSuccess(_userManager.Create(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = _userManager.GenerateTwoFactorToken(user.Id, factorId);
            Assert.NotNull(token);
            Assert.True(_userManager.VerifyTwoFactorToken(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public void EmailFactorFailsAfterSecurityStampChangeSyncTest()
        {
            SetupTests.SetupDatabase();
            const string factorId = "EmailCode";
            _userManager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = _userManager.GenerateTwoFactorToken(user.Id, factorId);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(_userManager.UpdateSecurityStamp(user.Id));
            Assert.False(_userManager.VerifyTwoFactorToken(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public async Task UserTwoFactorProviderTest()
        {
            SetupTests.SetupDatabase();
            const string factorId = "PhoneCode";
            _userManager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(await _userManager.SetTwoFactorEnabledAsync(user.Id, true));
            Assert.NotEqual(stamp, await _userManager.GetSecurityStampAsync(user.Id));
            Assert.True(await _userManager.GetTwoFactorEnabledAsync(user.Id));
        }

        [Fact]
        [TestMethod]
        public async Task SendSms()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.SmsService = messageService;
            var user = new IdentityUser("SmsTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            await _userManager.SendSmsAsync(user.Id, "Hi");
            Assert.NotNull(messageService.Message);
            Assert.Equal("Hi", messageService.Message.Body);
        }

        [Fact]
        [TestMethod]
        public async Task SendEmail()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.EmailService = messageService;
            var user = new IdentityUser("EmailTest") { Email = "foo@foo.com" };
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            await _userManager.SendEmailAsync(user.Id, "Hi", "Body");
            Assert.NotNull(messageService.Message);
            Assert.Equal("Hi", messageService.Message.Subject);
            Assert.Equal("Body", messageService.Message.Body);
        }

        [Fact]
        [TestMethod]
        public void SendSmsSync()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.SmsService = messageService;
            var user = new IdentityUser("SmsTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            _userManager.SendSms(user.Id, "Hi");
            Assert.NotNull(messageService.Message);
            Assert.Equal("Hi", messageService.Message.Body);
        }

        [Fact]
        [TestMethod]
        public void SendEmailSync()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.EmailService = messageService;
            var user = new IdentityUser("EmailTest") { Email = "foo@foo.com" };
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            _userManager.SendEmail(user.Id, "Hi", "Body");
            Assert.NotNull(messageService.Message);
            Assert.Equal("Hi", messageService.Message.Subject);
            Assert.Equal("Body", messageService.Message.Body);
        }

        [Fact]
        [TestMethod]
        public async Task PhoneTokenFactorTest()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.SmsService = messageService;
            const string factorId = "PhoneCode";
            _userManager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(await _userManager.NotifyTwoFactorTokenAsync(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal(token, messageService.Message.Body);
            Assert.True(await _userManager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public void PhoneTokenFactorSyncTest()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.SmsService = messageService;
            const string factorId = "PhoneCode";
            _userManager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = _userManager.GenerateTwoFactorToken(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(_userManager.NotifyTwoFactorToken(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal(token, messageService.Message.Body);
            Assert.True(_userManager.VerifyTwoFactorToken(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public async Task PhoneTokenFactorFormatTest()
        {
            SetupTests.SetupDatabase();
            var messageService = new TestMessageService();
            _userManager.SmsService = messageService;
            const string factorId = "PhoneCode";
            _userManager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>
            {
                MessageFormat = "Your code is: {0}"
            });
            var user = new IdentityUser("PhoneCodeTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(await _userManager.NotifyTwoFactorTokenAsync(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal("Your code is: " + token, messageService.Message.Body);
            Assert.True(await _userManager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public async Task NoFactorProviderTest()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("PhoneCodeTest");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            const string error = "No IUserTwoFactorProvider for 'bogus' is registered.";
            ExceptionHelper.ThrowsWithError<NotSupportedException>(
                () => _userManager.GenerateTwoFactorToken(user.Id, "bogus"), error);
            ExceptionHelper.ThrowsWithError<NotSupportedException>(
                () => _userManager.VerifyTwoFactorToken(user.Id, "bogus", "bogus"), error);
        }

        [Fact]
        [TestMethod]
        public async Task GetValidTwoFactorTestEmptyWithNoProviders()
        {
            SetupTests.SetupDatabase();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var factors = await _userManager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            Assert.True(!factors.Any());
        }

        [Fact]
        [TestMethod]
        public async Task GetValidTwoFactorTest()
        {
            SetupTests.SetupDatabase();
            _userManager.RegisterTwoFactorProvider("phone", new PhoneNumberTokenProvider<IdentityUser>());
            _userManager.RegisterTwoFactorProvider("email", new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var factors = await _userManager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            UnitTestHelper.IsSuccess(await _userManager.SetPhoneNumberAsync(user.Id, "111-111-1111"));
            factors = await _userManager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.False(factors.Any());
            // Need to confirm
            user.PhoneNumberConfirmed = true;
            UnitTestHelper.IsSuccess(_userManager.Update(user));
            factors = await _userManager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
            UnitTestHelper.IsSuccess(await _userManager.SetEmailAsync(user.Id, "test@test.com"));
            factors = await _userManager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            // Need to confirm
            user.EmailConfirmed = true;
            UnitTestHelper.IsSuccess(await _userManager.UpdateAsync(user));
            factors = await _userManager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 2);
            UnitTestHelper.IsSuccess(await _userManager.SetEmailAsync(user.Id, "somethingelse"));
            factors = await _userManager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
        }

        [Fact]
        [TestMethod]
        public void GetValidTwoFactorSyncTest()
        {
            SetupTests.SetupDatabase();
            _userManager.RegisterTwoFactorProvider("phone", new PhoneNumberTokenProvider<IdentityUser>());
            _userManager.RegisterTwoFactorProvider("email", new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(_userManager.Create(user));
            var factors = _userManager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.False(factors.Any());
            UnitTestHelper.IsSuccess(_userManager.SetPhoneNumber(user.Id, "111-111-1111"));
            factors = _userManager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.False(factors.Any());
            // Need to confirm
            user.PhoneNumberConfirmed = true;
            UnitTestHelper.IsSuccess(_userManager.Update(user));
            factors = _userManager.GetValidTwoFactorProviders(user.Id);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
            UnitTestHelper.IsSuccess(_userManager.SetEmail(user.Id, "test@test.com"));
            factors = _userManager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            // Need to confirm
            user.EmailConfirmed = true;
            UnitTestHelper.IsSuccess(_userManager.Update(user));
            factors = _userManager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 2);
            UnitTestHelper.IsSuccess(_userManager.SetEmail(user.Id, null));
            factors = _userManager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
        }

        [Fact]
        [TestMethod]
        public async Task PhoneFactorFailsAfterSecurityStampChangeTest()
        {
            SetupTests.SetupDatabase();
            var factorId = "PhoneCode";
            _userManager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest");
            user.PhoneNumber = "4251234567";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await _userManager.UpdateSecurityStampAsync(user.Id));
            Assert.False(await _userManager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        [TestMethod]
        public async Task WrongTokenProviderFailsTest()
        {
            SetupTests.SetupDatabase();
            var factorId = "PhoneCode";
            _userManager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            _userManager.RegisterTwoFactorProvider("EmailCode", new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest");
            user.PhoneNumber = "4251234567";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.False(await _userManager.VerifyTwoFactorTokenAsync(user.Id, "EmailCode", token));
        }

        [Fact]
        [TestMethod]
        public async Task WrongTokenFailsTest()
        {
            SetupTests.SetupDatabase();
            var factorId = "PhoneCode";
            _userManager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest");
            user.PhoneNumber = "4251234567";
            UnitTestHelper.IsSuccess(await _userManager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await _userManager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.False(await _userManager.VerifyTwoFactorTokenAsync(user.Id, factorId, "abc"));
        }

        [Fact]
        [TestMethod]
        public async Task ResetTokenCallNoopForTokenValueZero()
        {
            var user = new IdentityUser() { UserName = "foo" };
            var store = new Mock<UserStore<IdentityUser>>();
            store.Setup(x => x.ResetAccessFailedCountAsync(user)).Returns(() =>
            {
                throw new Exception();
            });
            store.Setup(x => x.FindByIdAsync(It.IsAny<string>()))
                .Returns(() => Task.FromResult(user));
            store.Setup(x => x.GetAccessFailedCountAsync(It.IsAny<IdentityUser>()))
                .Returns(() => Task.FromResult(0));
            var manager = new UserManager<IdentityUser>(store.Object);
            UnitTestHelper.IsSuccess(await manager.ResetAccessFailedCountAsync(user.Id));
        }

        [Fact]
        [TestMethod]
        public void Create_preserves_culture()
        {
            var originalCulture = Thread.CurrentThread.CurrentCulture;
            var originalUICulture = Thread.CurrentThread.CurrentUICulture;
            var expectedCulture = new CultureInfo("de-DE");
            Thread.CurrentThread.CurrentCulture = expectedCulture;
            Thread.CurrentThread.CurrentUICulture = expectedCulture;
            SetupTests.SetupDatabase();
            var manager = UnitTestHelper.CreateManager(_sqlServer); ;
            try
            {
                var cultures = GetCurrentCultureAfter(() => manager.CreateAsync(new IdentityUser("whatever"))).Result;
                Assert.Equal(expectedCulture, cultures.Item1);
                Assert.Equal(expectedCulture, cultures.Item2);
            }
            finally
            {
                Thread.CurrentThread.CurrentCulture = originalCulture;
                Thread.CurrentThread.CurrentUICulture = originalUICulture;
            }
        }

        [Fact]
        [TestMethod]
        public void CreateSync_preserves_culture()
        {
            var originalCulture = Thread.CurrentThread.CurrentCulture;
            var originalUICulture = Thread.CurrentThread.CurrentUICulture;
            var expectedCulture = new CultureInfo("de-DE");
            Thread.CurrentThread.CurrentCulture = expectedCulture;
            Thread.CurrentThread.CurrentUICulture = expectedCulture;
            SetupTests.SetupDatabase();

            try
            {
                var cultures = GetCurrentCultureAfter(() => _userManager.Create(new IdentityUser("whatever")));
                Assert.Equal(expectedCulture, cultures.Item1);
                Assert.Equal(expectedCulture, cultures.Item2);
            }
            finally
            {
                Thread.CurrentThread.CurrentCulture = originalCulture;
                Thread.CurrentThread.CurrentUICulture = originalUICulture;
            }
        }


        private static async Task<Tuple<CultureInfo, CultureInfo>> GetCurrentCultureAfter(Func<Task> action)
        {
            await action();
            return new Tuple<CultureInfo, CultureInfo>(Thread.CurrentThread.CurrentCulture, Thread.CurrentThread.CurrentUICulture);
        }

        private static Tuple<CultureInfo, CultureInfo> GetCurrentCultureAfter(Action action)
        {
            action();
            return new Tuple<CultureInfo, CultureInfo>(Thread.CurrentThread.CurrentCulture, Thread.CurrentThread.CurrentUICulture);
        }

        private class NoOpTokenProvider : IUserTokenProvider<IdentityUser, string>
        {
            public Task<string> GenerateAsync(string purpose, UserManager<IdentityUser, string> manager,
                IdentityUser user)
            {
                throw new NotImplementedException();
            }

            public Task<bool> ValidateAsync(string purpose, string token, UserManager<IdentityUser, string> manager,
                IdentityUser user)
            {
                throw new NotImplementedException();
            }

            public Task NotifyAsync(string token, UserManager<IdentityUser, string> manager, IdentityUser user)
            {
                throw new NotImplementedException();
            }

            public Task<bool> IsValidProviderForUserAsync(UserManager<IdentityUser, string> manager, IdentityUser user)
            {
                throw new NotImplementedException();
            }
        }

        private class NoopUserStore : IUserStore<IdentityUser>
        {
            public Task CreateAsync(IdentityUser user)
            {
                return Task.FromResult(0);
            }

            public Task UpdateAsync(IdentityUser user)
            {
                return Task.FromResult(0);
            }

            public Task<IdentityUser> FindByIdAsync(string userId)
            {
                return Task.FromResult<IdentityUser>(null);
            }

            public Task<IdentityUser> FindByNameAsync(string userName)
            {
                return Task.FromResult<IdentityUser>(null);
            }

            public void Dispose()
            {
            }

            public Task DeleteAsync(IdentityUser user)
            {
                return Task.FromResult(0);
            }
        }


    }


}
