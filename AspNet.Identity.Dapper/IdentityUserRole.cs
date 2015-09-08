using Dapper.Contrib.Extensions;

namespace AspNet.Identity.Dapper
{
    /// <summary>
    ///     EntityType that represents a user belonging to a role
    /// </summary>
   [Table("AspNetUserRoles")]
    public class IdentityUserRole : IdentityUserRole<string>
    {
    }

    /// <summary>
    ///     EntityType that represents a user belonging to a role
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    [Table("AspNetUserRoles")]
    public class IdentityUserRole<TKey>
    {
        /// <summary>
        ///     UserId for the user that is in the role
        /// </summary>
        public virtual TKey UserId { get; set; }

        /// <summary>
        ///     RoleId for the role
        /// </summary>
        public virtual TKey RoleId { get; set; }
    }
}