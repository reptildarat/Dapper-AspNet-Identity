using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Dapper.Contrib.Extensions
{
    public class MySqlAdapter : ISqlAdapter
    {
        private const string IdentityId = "SELECT LAST_INSERT_ID() id";
        /*
                * ms not contained in format. MySql ignores ms part anyway
                * 
                * for more details see: http://dev.mysql.com/doc/refman/5.1/en/datetime.html
                */
        private const string MySqlDateTimeFormat = "yyyy-MM-dd HH:mm:ss";

        public string LastInsertIdQuery
        {
            get { return IdentityId; }
        }

        public void BulkInsert<T>(IDbConnection db, List<T> entities, string tableName, List<PropertyInfo> prop) where T : class
        {
            const string query = "INSERT INTO {0} ({1}) VALUES {2}";
            const string separator = ", ";

            var theColumn = ExtractQuery(prop, separator, (c) => GetQuoteColumnName(c.Name));
            var theValue = new StringBuilder(null);

            foreach (var entity in entities)
            {
                theValue.Append("( ");
                theValue.Append(ExtractQuery(prop, separator, (c) => GetQuotedValue(c.GetValue(entity), c.GetType())));
                theValue.Append(" )");

                theValue.Append(separator);
            }

            var cmd = string.Format(query, tableName, theColumn, theValue.Remove(theValue.Length -2, 2));
            db.Execute(cmd);
        }

        private static string ExtractQuery(List<PropertyInfo> prop, string separator, Func<PropertyInfo, string> func)
        {
            var theColumn = new StringBuilder(prop.Count);

            foreach (PropertyInfo property in prop)
            {
                theColumn.AppendFormat("{0}", func.Invoke(property));
                theColumn.Append(separator);
            }

            theColumn.Remove(theColumn.Length -2, 1);

            return theColumn.ToString();
        }

        public async Task<int> InsertAsync(IDbConnection connection, IDbTransaction transaction, int? commandTimeout,
            string tableName,
            string columnList, string parameterList, IEnumerable<PropertyInfo> keyProperties, object entityToInsert)
        {
            string cmd = String.Format(BaseDialectProvider.InsertQuery, tableName, columnList, parameterList);

            await
                connection.ExecuteAsync(cmd, entityToInsert, transaction: transaction, commandTimeout: commandTimeout)
                    .ConfigureAwait(false);

            var r =
                await
                    connection.QueryAsync<dynamic>("SELECT LAST_INSERT_ID() id", transaction: transaction,
                        commandTimeout: commandTimeout).ConfigureAwait(false);
            int id = (int) r.First().id;
            if (keyProperties.Any())
                keyProperties.First().SetValue(entityToInsert, id, null);
            return id;
        }

        public string GetQuotedParam(string paramValue)
        {
            return "'" + paramValue.Replace("\\", "\\\\").Replace("'", @"\'") + "'";
        }

        public string GetQuotedValue(object value, Type fieldType)
        {
            if (fieldType == typeof (DateTime))
            {
                var dateValue = (DateTime) value;


                return BaseDialectProvider.GetQuotedValue(dateValue.ToString(MySqlDateTimeFormat), typeof (string), this);
            }

            if (fieldType == typeof (Guid))
            {
                var guidValue = (Guid) value;
                return BaseDialectProvider.GetQuotedValue(guidValue.ToString("N"), typeof (string), this);
            }

            if (fieldType == typeof (byte[]))
            {
                return "0x" + BitConverter.ToString((byte[]) value).Replace("-", "");
            }

            return BaseDialectProvider.GetQuotedValue(value, fieldType, this);
        }

        public string GetQuoteColumnName(string columnName)
        {
            return string.Format("`{0}`", columnName);
        }
    }
}