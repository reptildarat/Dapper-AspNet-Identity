using System;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Identity.Dapper.Contracts.Repository;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Xunit;

namespace AspNet.Identity.Dapper.SqlServer.Tests.Setup
{
    public static class UnitTestHelper
    {

        public static UserManager<IdentityUser> CreateManager(IConnectionRepository db)
        {
            var options = new IdentityFactoryOptions<UserManager<IdentityUser>>
            {
                Provider = new TestProvider(db),
                DataProtectionProvider = new DpapiDataProtectionProvider()
            };
            return options.Provider.Create(options, new OwinContext());
        }

        public static bool EnglishBuildAndOS
        {
            get
            {
                var englishBuild = string.Equals(CultureInfo.CurrentUICulture.TwoLetterISOLanguageName, "en",
                    StringComparison.OrdinalIgnoreCase);
                var englishOS = string.Equals(CultureInfo.CurrentCulture.TwoLetterISOLanguageName, "en",
                    StringComparison.OrdinalIgnoreCase);
                return englishBuild && englishOS;
            }
        }

        public static void IsSuccess(IdentityResult result)
        {
            Assert.NotNull(result);
            Assert.True(result.Succeeded);
        }

        public static void IsFailure(IdentityResult result)
        {
            Assert.NotNull(result);
            Assert.False(result.Succeeded);
        }

        public static void IsFailure(IdentityResult result, string error)
        {
            Assert.NotNull(result);
            Assert.False(result.Succeeded);
            Assert.Equal(error, result.Errors.First());
        }

        public class AlwaysBadValidator<T> : IIdentityValidator<T>
        {
            public const string ErrorMessage = "I'm Bad.";

            public Task<IdentityResult> ValidateAsync(T item)
            {
                return Task.FromResult(IdentityResult.Failed(ErrorMessage));
            }
        }

        public class NoopValidator<T> : IIdentityValidator<T>
        {
            public Task<IdentityResult> ValidateAsync(T item)
            {
                return Task.FromResult(IdentityResult.Success);
            }
        }
    }
}