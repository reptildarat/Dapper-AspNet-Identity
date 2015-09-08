using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace Dapper.Contrib.Extensions
{
    public static partial class SqlMapperExtensions
    {
        /// <summary>
        /// Inserts an entity into table "Ts" asynchronously using .NET 4.5 Task and returns identity id.
        /// </summary>
        /// <param name="connection">Open SqlConnection</param>
        /// <param name="entityToInsert">Entity to insert</param>
        /// <returns>Identity of inserted entity</returns>
        public static Task<int> InsertAsync<T>(this IDbConnection connection, T entityToInsert, 
            IDbTransaction transaction = null, int? commandTimeout = null) where T : class
        {

            var type = typeof(T);

            var name = GetTableName(type);

            var sbColumnList = new StringBuilder(null);

            var keyProperties = KeyPropertiesCache(type).ToList();
            var allPropertiesExceptKeyAndComputed = AllPropertiesExceptKeyAndComputed(type);

            for (var i = 0; i < allPropertiesExceptKeyAndComputed.Count(); i++)
            {
                var property = allPropertiesExceptKeyAndComputed.ElementAt(i);
                sbColumnList.AppendFormat("[{0}]", property.Name);
                if (i < allPropertiesExceptKeyAndComputed.Count() - 1)
                    sbColumnList.Append(", ");
            }

            var sbParameterList = new StringBuilder(null);
            for (var i = 0; i < allPropertiesExceptKeyAndComputed.Count(); i++)
            {
                var property = allPropertiesExceptKeyAndComputed.ElementAt(i);
                sbParameterList.AppendFormat("@{0}", property.Name);
                if (i < allPropertiesExceptKeyAndComputed.Count() - 1)
                    sbParameterList.Append(", ");
            }

            ISqlAdapter adapter = GetFormatter(connection);
            return adapter.InsertAsync(connection, transaction, commandTimeout, name, sbColumnList.ToString(), sbParameterList.ToString(), keyProperties, entityToInsert);
        }

        public static Task InsertAllAsync<T>(this IDbConnection connection, T entityToInsert,
            IDbTransaction transaction = null, int? commandTimeout = null) where T : class
        {
            return null;
        }
    }
}