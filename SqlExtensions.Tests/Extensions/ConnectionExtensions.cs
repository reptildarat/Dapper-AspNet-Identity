using System;
using System.Data;

namespace Dapper.Contrib.Extensions
{
    public static partial class SqlMapperExtensions
    {
        public static bool TransactionActive;

        public static void WithTransaction(this IDbConnection conn, Action<IDbConnection> action)
        {
            TransactionActive = true;

            using (var trans = conn.BeginTransaction(IsolationLevel.Serializable))
            {
                action.Invoke(conn);
                trans.Commit();
                TransactionActive = false;
            }

            conn.Dispose();
        }
    }
}