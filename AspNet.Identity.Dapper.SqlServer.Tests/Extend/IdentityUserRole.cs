using System.ComponentModel.DataAnnotations;
using ServiceStack.DataAnnotations;

namespace AspNet.Identity.Dapper.SqlServer.Tests.Extend
{
    /// <summary>
    ///     EntityType that represents a user belonging to a role
    /// </summary>
    [Alias("AspNetUserRoles")]
    public class IdentityUserRole : IdentityUserRole<string>
    {
    }

    /// <summary>
    ///     EntityType that represents a user belonging to a role
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    [Alias("AspNetUserRoles")]
    public class IdentityUserRole<TKey>
    {
        /// <summary>
        ///     UserId for the user that is in the role
        /// </summary>
        [PrimaryKey]
        [Required]
        [StringLength(128)]
        [References(typeof(IdentityUser))]

        public virtual TKey UserId { get; set; }

        /// <summary>
        ///     RoleId for the role
        /// </summary>
        [StringLength(128)]
        [References(typeof(IdentityRole))]
        [Required]
        public virtual TKey RoleId { get; set; }
    }
}