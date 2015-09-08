using System;
using System.Data;
using System.Text;
using Dapper;

namespace Dapper.Contrib.Extensions
{
    public static partial class SqlMapperExtensions
    {
        /// <summary>
        /// Updates entity in table "Ts", checks if the entity is modified if the entity is tracked by the Get() extension.
        /// </summary>
        /// <typeparam name="T">Type to be updated</typeparam>
        /// <param name="connection">Open SqlConnection</param>
        /// <param name="entityToUpdate">Entity to be updated</param>
        /// <returns>true if updated, false if not found or not modified (tracked entities)</returns>
        public static bool Update<T>(this IDbConnection connection, T entityToUpdate, IDbTransaction transaction = null, int? commandTimeout = null) where T : class
        {
            var proxy = entityToUpdate as IProxy;
            if (proxy != null)
            {
                if (!proxy.IsDirty) return false;
            }

            var type = typeof(T);

            var keyProperties = KeyPropertiesCache(type);
            if (!keyProperties.Any())
                throw new ArgumentException("Entity must have at least one [Key] property");

            var name = GetTableName(type);

            var sb = new StringBuilder();
            sb.AppendFormat("UPDATE {0} SET ", name);

            var allProperties = TypePropertiesCache(type);
            var computedProperties = ComputedPropertiesCache(type);
            var nonIdProps = allProperties.Except(keyProperties.Union(computedProperties)).ToList();

            for (var i = 0; i < nonIdProps.Count(); i++)
            {
                var property = nonIdProps.ElementAt(i);
                sb.AppendFormat("{0} = @{1}", property.Name, property.Name);
                if (i < nonIdProps.Count() - 1)
                    sb.AppendFormat(", ");
            }
            sb.Append(" WHERE ");
            for (var i = 0; i < keyProperties.Count(); i++)
            {
                var property = keyProperties.ElementAt(i);

                sb.AppendFormat("{0} = @{1}", property.Name, property.Name);
                if (i < keyProperties.Count() - 1)
                    sb.AppendFormat(" AND ");
            }



            var updated = connection.Execute(sb.ToString(), entityToUpdate, commandTimeout: commandTimeout, transaction: transaction);
            return updated > 0;
        } 
    }
}