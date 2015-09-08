using System;
using System.Collections.Generic;
using System.Data;
using System.Reflection;
using System.Threading.Tasks;

namespace Dapper.Contrib.Extensions
{
    public interface ISqlAdapter : IReadDialectProvider, IDialectProvider, IWriteDialectProvider
    {
        Task<int> InsertAsync(IDbConnection connection, IDbTransaction transaction, int? commandTimeout, String tableName, string columnList, string parameterList, IEnumerable<PropertyInfo> keyProperties, object entityToInsert);
    }
}