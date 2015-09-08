using System;
using System.Collections.Generic;
using Dapper.Contrib.Extensions;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Dapper
{
    [Table("AspNetRoles")]
    public class IdentityRole : IdentityRole<string, IdentityUserRole>
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

    [Table("AspNetRoles")]
    public class IdentityRole<TKey, TUserRole> : IRole<TKey> where TUserRole : IdentityUserRole<TKey>
    {
        /// <summary>
        /// Default constructor for Role 
        /// </summary>
        public IdentityRole()
        {
            Users = new List<TUserRole>();
        }

        /// <summary>
        ///     Navigation property for users in the role
        /// </summary>
        [Write(false)]
        public virtual ICollection<TUserRole> Users { get; private set; }

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
       
        public TKey Id { get; set; }

        /// <summary>
        /// Role name
        /// </summary>
        public string Name { get; set; }
    }
}