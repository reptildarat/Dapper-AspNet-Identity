using System;
using System.Data;
using System.Text;
using Dapper;

namespace Dapper.Contrib.Extensions
{
    public static partial class SqlMapperExtensions
    {
        /// <summary>
        /// Delete entity in table "Ts".
        /// </summary>
        /// <typeparam name="T">Type of entity</typeparam>
        /// <param name="connection">Open SqlConnection</param>
        /// <param name="entityToDelete">Entity to delete</param>
        /// <returns>true if deleted, false if not found</returns>
        public static bool Delete<T>(this IDbConnection connection, T entityToDelete, IDbTransaction transaction = null,
            int? commandTimeout = null) where T : class
        {
            if (entityToDelete == null)
                throw new ArgumentException("Cannot Delete null Object", "entityToDelete");

            var type = typeof(T);

            var keyProperties = KeyPropertiesCache(type).ToList();
            if (!keyProperties.Any())
                throw new ArgumentException("Entity must have at least one [Key] property");

            var name = GetTableName(type);

            var sb = new StringBuilder();
            sb.AppendFormat("DELETE FROM {0} WHERE ", name);

            for (var i = 0; i < keyProperties.Count(); i++)
            {
                var property = keyProperties.ElementAt(i);
                sb.AppendFormat("{0} = @{1}", property.Name, property.Name);
                if (i < keyProperties.Count() - 1)
                    sb.AppendFormat(" AND ");
            }
            var deleted = connection.Execute(sb.ToString(), entityToDelete, transaction: transaction,
                commandTimeout: commandTimeout);
            return deleted > 0;
        }

        /// <summary>
        /// Delete all entities in the table related to the type T.
        /// </summary>
        /// <typeparam name="T">Type of entity</typeparam>
        /// <param name="connection">Open SqlConnection</param>
        /// <returns>true if deleted, false if none found</returns>
        public static bool DeleteAll<T>(this IDbConnection connection, IDbTransaction transaction = null,
            int? commandTimeout = null) where T : class
        {
            var type = typeof(T);
            var name = GetTableName(type);
            var statement = String.Format("DELETE FROM {0}", name);
            var deleted = connection.Execute(statement, null, transaction: transaction, commandTimeout: commandTimeout);
            return deleted > 0;
        }
    }
}