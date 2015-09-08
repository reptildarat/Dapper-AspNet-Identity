using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Dapper;

namespace Dapper.Contrib.Extensions
{
    public class PostgresAdapter : ISqlAdapter
    {
        public int Insert(IDbConnection connection, IDbTransaction transaction, int? commandTimeout, String tableName, string columnList, string parameterList, IEnumerable<PropertyInfo> keyProperties, object entityToInsert)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("INSERT INTO {0} ({1}) VALUES ({2})", tableName, columnList, parameterList);

            // If no primary key then safe to assume a join table with not too much data to return
            if (!keyProperties.Any())
                sb.Append(" RETURNING *");
            else
            {
                sb.Append(" RETURNING ");
                bool first = true;
                foreach (var property in keyProperties)
                {
                    if (!first)
                        sb.Append(", ");
                    first = false;
                    sb.Append(property.Name);
                }
            }

            var results = connection.Query(sb.ToString(), entityToInsert, transaction: transaction, commandTimeout: commandTimeout);

            // Return the key by assinging the corresponding property in the object - by product is that it supports compound primary keys
            int id = 0;
            foreach (var p in keyProperties)
            {
                var value = ((IDictionary<string, object>)results.First())[p.Name.ToLower()];
                p.SetValue(entityToInsert, value, null);
                if (id == 0)
                    id = Convert.ToInt32(value);
            }
            return id;
        }

        public async Task<int> InsertAsync(IDbConnection connection, IDbTransaction transaction, int? commandTimeout, String tableName, string columnList, string parameterList, IEnumerable<PropertyInfo> keyProperties, object entityToInsert)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("INSERT INTO {0} ({1}) VALUES ({2})", tableName, columnList, parameterList);

            // If no primary key then safe to assume a join table with not too much data to return
            if (!keyProperties.Any())
                sb.Append(" RETURNING *");
            else
            {
                sb.Append(" RETURNING ");
                bool first = true;
                foreach (var property in keyProperties)
                {
                    if (!first)
                        sb.Append(", ");
                    first = false;
                    sb.Append(property.Name);
                }
            }

            var results = await connection.QueryAsync<dynamic>(sb.ToString(), entityToInsert, transaction: transaction, commandTimeout: commandTimeout).ConfigureAwait(false);

            // Return the key by assinging the corresponding property in the object - by product is that it supports compound primary keys
            int id = 0;
            foreach (var p in keyProperties)
            {
                var value = ((IDictionary<string, object>)results.First())[p.Name.ToLower()];
                p.SetValue(entityToInsert, value, null);
                if (id == 0)
                    id = Convert.ToInt32(value);
            }
            return id;
        }

        public string GetQuotedParam(string paramValue)
        {
            throw new NotImplementedException();
        }

        public string GetQuotedValue(object value, Type fieldType)
        {
            throw new NotImplementedException();
        }

        public string GetQuoteColumnName(string columnName)
        {
            throw new NotImplementedException();
        }

        public string LastInsertIdQuery { get; private set; }
        public void BulkInsert<T>(IDbConnection db, List<T> entities, string tableName, List<PropertyInfo> prop) where T : class
        {
            throw new NotImplementedException();
        }
    }
}