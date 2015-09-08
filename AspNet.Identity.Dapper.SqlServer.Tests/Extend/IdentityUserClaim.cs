using System.ComponentModel.DataAnnotations;
using Dapper.Contrib.Extensions;
using ServiceStack.DataAnnotations;

namespace AspNet.Identity.Dapper.SqlServer.Tests.Extend
{
    /// <summary>
    ///     EntityType that represents one specific user claim
    /// </summary>
    [Alias("AspNetUserClaims")]
    public class IdentityUserClaim : IdentityUserClaim<string>
    {
    }

    /// <summary>
    ///     EntityType that represents one specific user claim
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    [Alias("AspNetUserClaims")]
    public class IdentityUserClaim<TKey>
    {
        /// <summary>
        ///     Primary key
        /// </summary>
        [PrimaryKey]
        [AutoIncrement]
        public virtual int Id { get; set; }

        /// <summary>
        ///     User Id for the user who owns this login
        /// </summary>
        [References(typeof(IdentityUser))]
        [StringLength(128)]
        [Required]
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