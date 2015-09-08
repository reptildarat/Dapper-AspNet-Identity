using System.Collections.Generic;
using System.Data;
using System.Reflection;

namespace Dapper.Contrib.Extensions
{
    public interface IWriteDialectProvider
    {
        

        void BulkInsert<T>(IDbConnection db, List<T> entities, string tableName, List<PropertyInfo> prop) where T : class;

    }
}