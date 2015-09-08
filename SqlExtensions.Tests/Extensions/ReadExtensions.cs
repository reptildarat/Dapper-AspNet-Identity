using System.Data;
using Dapper;

namespace Dapper.Contrib.Extensions
{
    public static partial class SqlMapperExtensions
    {
        public static long GetLastInsertId(this IDbConnection db)
        {
            return db.ExecuteScalar<long>(GetFormatter(db).LastInsertIdQuery);
        } 
    }
}