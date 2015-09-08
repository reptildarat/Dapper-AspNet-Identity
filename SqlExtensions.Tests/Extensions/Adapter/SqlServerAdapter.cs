using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Dapper.Contrib.Extensions
{
    public class SqlServerAdapter : ISqlAdapter
    {
        private const string IdQuery = "SELECT @@IDENTITY id";
        public int Insert(IDbConnection connection, IDbTransaction transaction, int? commandTimeout, string tableName, string columnList, string parameterList, IEnumerable<PropertyInfo> keyProperties, object entityToInsert)
        {
            string cmd = String.Format(BaseDialectProvider.InsertQuery, tableName, columnList, parameterList);

            connection.Execute(cmd, entityToInsert, transaction: transaction, commandTimeout: commandTimeout);

            //NOTE: would prefer to use IDENT_CURRENT('tablename') or IDENT_SCOPE but these are not available on SQLCE
            var r = connection.Query(IdQuery, transaction: transaction, commandTimeout: commandTimeout);
            int id = (int)r.First().id;
            if (keyProperties.Any())
                keyProperties.First().SetValue(entityToInsert, id, null);
            return id;
        }

        public async Task<int> InsertAsync(IDbConnection connection, IDbTransaction transaction, int? commandTimeout, String tableName, string columnList, string parameterList, IEnumerable<PropertyInfo> keyProperties, object entityToInsert)
        {
            string cmd = String.Format("INSERT INTO {0} ({1}) VALUES ({2})", tableName, columnList, parameterList);

            await connection.ExecuteAsync(cmd, entityToInsert, transaction: transaction, commandTimeout: commandTimeout).ConfigureAwait(false);

            //NOTE: would prefer to use IDENT_CURRENT('tablename') or IDENT_SCOPE but these are not available on SQLCE
            var r = await connection.QueryAsync<dynamic>("SELECT @@IDENTITY id", transaction: transaction, commandTimeout: commandTimeout).ConfigureAwait(false);
            int id = (int)r.First().id;
            if (keyProperties.Any())
                keyProperties.First().SetValue(entityToInsert, id, null);
            return id;
        }

        public string GetQuotedParam(string paramValue)
        {
            return "'" + paramValue.Replace("'", "''") + "'";
        }

        public string GetQuotedValue(object value, Type fieldType)
        {
            if (value == null) return "NULL";

            if (fieldType == typeof(Guid))
            {
                var guidValue = (Guid)value;
                return string.Format("CAST('{0}' AS UNIQUEIDENTIFIER)", guidValue);
            }
            if (fieldType == typeof(DateTime))
            {
                var dateValue = (DateTime)value;
                if (dateValue.Kind == DateTimeKind.Local)
                    dateValue = dateValue.ToUniversalTime();
                const string iso8601Format = "yyyyMMdd HH:mm:ss.fff";
                return BaseDialectProvider.GetQuotedValue(dateValue.ToString(iso8601Format, CultureInfo.InvariantCulture), typeof(string), this);
            }
            if (fieldType == typeof(DateTimeOffset))
            {
                var dateValue = (DateTimeOffset)value;
                const string iso8601Format = "yyyyMMdd HH:mm:ss.fff zzz";
                return BaseDialectProvider.GetQuotedValue(dateValue.ToString(iso8601Format, CultureInfo.InvariantCulture), typeof(string), this);
            }
            if (fieldType == typeof(bool))
            {
                var boolValue = (bool)value;
                return BaseDialectProvider.GetQuotedValue(boolValue ? 1 : 0, typeof(int), this);
            }
            if (fieldType == typeof(string))
            {
                return GetQuotedParam(value.ToString());
            }

            if (fieldType == typeof(byte[]))
            {
                return "0x" + BitConverter.ToString((byte[])value).Replace("-", "");
            }

            return BaseDialectProvider.GetQuotedValue(value, fieldType, this);
        }

        public string GetQuoteColumnName(string columnName)
        {
            return string.Format("\"{0}\"", columnName);
        }

        public string LastInsertIdQuery
        {
            get { return IdQuery; }
        }

        public void BulkInsert<T>(IDbConnection db, List<T> entities, string tableName, List<PropertyInfo> prop)
            where T : class
        {
            using (var bulkCopy = new SqlBulkCopy(db.ConnectionString))
            {
                bulkCopy.BatchSize = entities.Count;
                bulkCopy.DestinationTableName = tableName;
                var table = new DataTable();

                foreach (var propertyInfo in prop)
                {
                    bulkCopy.ColumnMappings.Add(propertyInfo.Name, propertyInfo.Name);
                    table.Columns.Add(propertyInfo.Name,
                        Nullable.GetUnderlyingType(propertyInfo.PropertyType) ?? propertyInfo.PropertyType);
                }

                var values = new object[prop.Count];
                foreach (var item in entities)
                {
                    for (var i = 0; i < values.Length; i++)
                    {
                        values[i] = prop[i].GetValue(item);
                    }

                    table.Rows.Add(values);
                }

                bulkCopy.WriteToServer(table);
                table.Dispose();
            }
        }
    }
}