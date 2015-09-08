using System.ComponentModel.DataAnnotations;
using Dapper.Contrib.Extensions;
using ServiceStack.DataAnnotations;

namespace AspNet.Identity.Dapper.SqlServer.Tests.Extend
{
    /// <summary>
    ///     Entity type for a user's login (i.e. facebook, google)
    /// </summary>
    [Alias("AspNetUserLogins")]
    public class IdentityUserLogin : IdentityUserLogin<string>
    {
    }

    /// <summary>
    ///     Entity type for a user's login (i.e. facebook, google)
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    [Alias("AspNetUserLogins")]
    public class IdentityUserLogin<TKey>
    {
        /// <summary>
        ///     The login provider for the login (i.e. facebook, google)
        /// </summary>
        [PrimaryKey]
        public virtual string LoginProvider { get; set; }

        /// <summary>
        ///     Key representing the login for the provider
        /// </summary>
        [Required]
        public virtual string ProviderKey { get; set; }

        /// <summary>
        ///     User Id for the user who owns this login
        /// </summary>
        [References(typeof(IdentityUser))]
        [StringLength(128)]
        [Required]
        public virtual TKey UserId { get; set; }
    }
}