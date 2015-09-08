using System.Threading.Tasks;
using AspNet.Identity.Dapper.Contracts.Repository;
using AspNet.Identity.Dapper.Repository;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.DataProtection;

namespace AspNet.Identity.Dapper.SqlServer.Tests
{
    public class UserManagerConfig
    {
         
    }

   

    public class TestProvider : IdentityFactoryProvider<UserManager<IdentityUser>>
    {
        public TestProvider(IConnectionRepository db)
        {
            OnCreate = ((options, context) =>
            {
                var manager =
                    new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
                manager.UserValidator = new UserValidator<IdentityUser>(manager)
                {
                    AllowOnlyAlphanumericUserNames = true,
                    RequireUniqueEmail = false
                };
                manager.EmailService = new TestMessageService();
                manager.SmsService = new TestMessageService();
                if (options.DataProtectionProvider != null)
                {
                    manager.UserTokenProvider =
                        new DataProtectorTokenProvider<IdentityUser>(
                            options.DataProtectionProvider.Create("ASP.NET Identity"));
                }
                return manager;
            });
        }
    }

    public class TestMessageService : IIdentityMessageService
    {
        public IdentityMessage Message { get; set; }

        public Task SendAsync(IdentityMessage message)
        {
            Message = message;
            return Task.FromResult(0);
        }
    }
}