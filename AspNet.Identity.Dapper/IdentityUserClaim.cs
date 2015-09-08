using Dapper.Contrib.Extensions;

namespace AspNet.Identity.Dapper
{
    /// <summary>
    ///     EntityType that represents one specific user claim
    /// </summary>
    [Table("AspNetUserClaims")]
    public class IdentityUserClaim : IdentityUserClaim<string>
    {
    }

    /// <summary>
    ///     EntityType that represents one specific user claim
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    [Table("AspNetUserClaims")]
    public class IdentityUserClaim<TKey>
    {
        /// <summary>
        ///     Primary key
        /// </summary>
        [Key]
        public virtual int Id { get; set; }

        /// <summary>
        ///     User Id for the user who owns this login
        /// </summary>
        public virtual TKey UserId { get; set; }

        /// <summary>
        ///     Claim type
        /// </summary>
        public virtual string ClaimType { get; set; }

        /// <summary>
        ///     Claim value
        /// </summary>
        public virtual string ClaimValue { get; set; }
    }
}