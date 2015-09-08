using Dapper.Contrib.Extensions;

namespace AspNet.Identity.Dapper
{
    /// <summary>
    ///     Entity type for a user's login (i.e. facebook, google)
    /// </summary>
    [Table("AspNetUserLogins")]
    public class IdentityUserLogin : IdentityUserLogin<string>
    {
    }

    /// <summary>
    ///     Entity type for a user's login (i.e. facebook, google)
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    [Table("AspNetUserLogins")]
    public class IdentityUserLogin<TKey>
    {
        /// <summary>
        ///     The login provider for the login (i.e. facebook, google)
        /// </summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>
        ///     Key representing the login for the provider
        /// </summary>
        public virtual string ProviderKey { get; set; }

        /// <summary>
        ///     User Id for the user who owns this login
        /// </summary>
        [Key]
        public virtual TKey UserId { get; set; }
    }
}