using System;
using System.Collections.Generic;
using System.Data;
using AspNet.Identity.Dapper.Repository.SqlServer;

namespace AspNet.Identity.Dapper.Contracts.Repository
{
    public interface IConnectionRepository : IConnectionRepositoryAsync, IIdentityDapperQueryProvider
    {
        void WithTransaction(Action<IDbConnection> actions);
        void WithConnection(Action<IDbConnection> actions);
        T WithConnection<T>(Func<IDbConnection, T> func);

        IEnumerable<T> WithConnection<T>(Func<IDbConnection, IEnumerable<T>> func);
    }
}