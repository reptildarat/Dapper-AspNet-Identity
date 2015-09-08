using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNet.Identity;
using ServiceStack.DataAnnotations;

namespace AspNet.Identity.Dapper.SqlServer.Tests.Extend
{
    [Alias("AspNetRoles")]
    public class IdentityRole : IdentityRole<string>
    {
        public IdentityRole()
        {
            Id = Guid.NewGuid().ToString();
        }

        public IdentityRole(string name)
            : base(Guid.NewGuid().ToString(), name)
        {
        }

        public IdentityRole(string id, string name)
            : base(id, name)
        {
        }
    }

    [Alias("AspNetRoles")]
    public class IdentityRole<TKey> : IRole<TKey>
    {
        /// <summary>
        /// Default constructor for Role 
        /// </summary>
        public IdentityRole() {}

        /// <summary>
        /// Constructor that takes names as argument 
        /// </summary>
        /// <param name="name"></param>
        public IdentityRole(string name)
            : this()
        {
            Name = name;
        }

        public IdentityRole(TKey id, string name)
            : this(name)
        {
            Id = id;
        }

        /// <summary>
        /// Role ID
        /// </summary>
        [PrimaryKey]
        [StringLength(128)]
        public TKey Id { get; set; }

        /// <summary>
        /// Role name
        /// </summary>
        [Index(Unique = true)]
        [Required]
        public string Name { get; set; }
    }
}