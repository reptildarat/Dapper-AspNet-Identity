using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Dapper;

namespace Dapper.Contrib.Extensions
{
    public class SQLiteAdapter : ISqlAdapter
    {

        private const string SqlLiteDateTimeFormat = "yyyy-MM-dd HH:mm:ss";
        private const string IdQuery = "SELECT LAST_INSERT_ROWID() id";

        public int Insert(IDbConnection connection, IDbTransaction transaction, int? commandTimeout, String tableName, string columnList, string parameterList, IEnumerable<PropertyInfo> keyProperties, object entityToInsert)
        {
            string cmd = String.Format(BaseDialectProvider.InsertQuery, tableName, columnList, parameterList);

            connection.Execute(cmd, entityToInsert, transaction: transaction, commandTimeout: commandTimeout);

            var r = connection.Query("SELECT last_insert_rowid() id", transaction: transaction, commandTimeout: commandTimeout);
            int id = (int)r.First().id;
            if (keyProperties.Any())
                keyProperties.First().SetValue(entityToInsert, id, null);
            return id;
        }

        public async Task<int> InsertAsync(IDbConnection connection, IDbTransaction transaction, int? commandTimeout, String tableName, string columnList, string parameterList, IEnumerable<PropertyInfo> keyProperties, object entityToInsert)
        {
            string cmd = String.Format("INSERT INTO {0} ({1}) VALUES ({2})", tableName, columnList, parameterList);

            await connection.ExecuteAsync(cmd, entityToInsert, transaction: transaction, commandTimeout: commandTimeout).ConfigureAwait(false);

            var r = await connection.QueryAsync<dynamic>("SELECT last_insert_rowid() id", transaction: transaction, commandTimeout: commandTimeout).ConfigureAwait(false);
            int id = (int)r.First().id;
            if (keyProperties.Any())
                keyProperties.First().SetValue(entityToInsert, id, null);
            return id;
        }

        public string GetQuotedParam(string paramValue)
        {
            return BaseDialectProvider.GetQuotedParam(paramValue);
        }

        public string GetQuotedValue(object value, Type fieldType)
        {
            if (fieldType == typeof(Guid))
            {
                var guidValue = (Guid)value;
                return BaseDialectProvider.GetQuotedValue(guidValue.ToString("N"), typeof(string), this);
            }
            if (fieldType == typeof(DateTime))
            {
                var dateValue = (DateTime)value;
                return BaseDialectProvider.GetQuotedValue(dateValue.ToString(SqlLiteDateTimeFormat),
                    typeof(string), this);
            }

            if (fieldType == typeof(bool))
            {
                var boolValue = (bool)value;
                return BaseDialectProvider.GetQuotedValue(boolValue ? 1 : 0, typeof(int), this);
            }

            // output datetimeoffset as a string formatted for roundtripping.
            if (fieldType == typeof(DateTimeOffset))
            {
                var dateTimeOffsetValue = (DateTimeOffset)value;
                return BaseDialectProvider.GetQuotedValue(dateTimeOffsetValue.ToString("o"), typeof(string), this);
            }

            return BaseDialectProvider.GetQuotedValue(value, fieldType, this);
        }

        public string GetQuoteColumnName(string columnName)
        {
            return BaseDialectProvider.GetQuotedColumnName(columnName);
        }

        public string LastInsertIdQuery
        {
            get { return IdQuery; }
        }

        public void BulkInsert<T>(IDbConnection db, List<T> entities, string tableName, List<PropertyInfo> prop) where T : class
        {
            
        }
    }
}