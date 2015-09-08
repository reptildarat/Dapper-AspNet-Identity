using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Dapper.Contrib.Extensions
{
    public static partial class SqlMapperExtensions
    {
        /// <summary>
        /// Inserts an entity into table "Ts" and returns identity id.
        /// </summary>
        /// <param name="connection">Open SqlConnection</param>
        /// <param name="entityToInsert">Entity to insert</param>
        /// <returns>Identity of inserted entity</returns>
        public static void Insert<T>(this IDbConnection connection, T entityToInsert, IDbTransaction transaction = null,
            int? commandTimeout = null) where T : class
        {
            var type = typeof(T);
            var name = GetTableName(type);

            ISqlAdapter adapter = GetFormatter(connection);

            var allPropertiesExceptKeyAndComputed = AllPropertiesExceptKeyAndComputed(type);

            var cmd = ComposeInsertQuery(entityToInsert, allPropertiesExceptKeyAndComputed, adapter, name);
            connection.Execute(cmd, transaction: transaction, commandTimeout: commandTimeout);
        }

        // <summary>
        /// Inserts an entity into table "Ts" and returns identity id or number if inserted rows if inserting a list.
        /// </summary>
        /// <param name="connection">Open SqlConnection</param>
        /// <param name="entityToInsert">Entity to insert, can be list of entities</param>
        /// <returns>Identity of inserted entity, or number of inserted rows if inserting a list</returns>
        public static long Insert<T>(this IDbConnection connection, T entityToInsert, IDbTransaction transaction = null,
            int? commandTimeout = null) where T : class
        {
            
        }


        public static void InsertAll<T>(this IDbConnection connection, List<T> entityToInsert) where T : class
        {
            var adapter = GetFormatter(connection);
            var theType = typeof(T);

            //if (!TransactionActive)
            //{
            //    using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
            //    {
            //        adapter.BulkInsert(connection, entityToInsert, GetTableName(theType),
            //            AllPropertiesExceptKeyAndComputed(theType));
            //        transaction.Commit();
            //        return;
            //    }
            //}

            adapter.BulkInsert(connection, entityToInsert, GetTableName(theType), AllPropertiesExceptKeyAndComputed(theType));
        }

        private static string ComposeInsertQuery<T>(T entityToInsert, List<PropertyInfo> allPropertiesExceptKeyAndComputed, ISqlAdapter adapter,
    string name) where T : class
        {
            var sbColumnList = new StringBuilder(null);
            var sbParameterList = new StringBuilder(null);
            const string separator = ", ";
            for (var i = 0; i < allPropertiesExceptKeyAndComputed.Count(); i++)
            {
                var property = allPropertiesExceptKeyAndComputed.ElementAt(i);
                sbColumnList.AppendFormat("{0}", adapter.GetQuoteColumnName(property.Name));

                sbParameterList.AppendFormat("{0}",
                    adapter.GetQuotedValue(property.GetValue(entityToInsert), property.GetType()));

                if (i < allPropertiesExceptKeyAndComputed.Count() - 1)
                {
                    sbColumnList.Append(separator);
                    sbParameterList.Append(separator);
                }
            }

            string cmd = String.Format(BaseDialectProvider.InsertQuery, name, sbColumnList, sbParameterList);
            return cmd;
        }

        public static string foo(string oncom)
        {
            
        }

        public static void foo(string oncom)
        {
            
        }
    }
}