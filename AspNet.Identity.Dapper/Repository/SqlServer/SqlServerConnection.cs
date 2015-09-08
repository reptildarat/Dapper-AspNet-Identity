using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Threading.Tasks;
using AspNet.Identity.Dapper.Contracts.Repository;

namespace AspNet.Identity.Dapper.Repository.SqlServer
{
    public class SqlServerConnection : SqlServerQuery, IConnectionRepository
    {
        private readonly IDbConnection _connection;


        public SqlServerConnection(IDbConnection connection)
        {
            _connection = connection;
        }

        public void WithTransaction(Action<IDbConnection> actions)
        {
            using (_connection)
            {
                _connection.Open();

                using (var context = _connection.BeginTransaction())
                {
                    actions.Invoke(_connection);
                    context.Commit();
                }
            }
        }

        public void WithConnection(Action<IDbConnection> actions)
        {
            using (_connection)
            {
                actions.Invoke(_connection);
            }
        }

        public T WithConnection<T>(Func<IDbConnection, T> func)
        {
            using (_connection)
            {
                _connection.Open();
                return func.Invoke(_connection);
            }
        }

        public IEnumerable<T> WithConnection<T>(Func<IDbConnection, IEnumerable<T>> func)
        {
            using (_connection)
            {
                _connection.Open();
                return func.Invoke(_connection);
            }
        }

        public async Task WithTransactionAsync(Func<IDbConnection, Task> actions)
        {
            using (_connection)
            {
                _connection.Open();
                using (var context = _connection.BeginTransaction())
                {
                    await actions.Invoke(_connection);
                    context.Commit();

                }
            }
        }

        public async Task<T> WithConnectionAsync<T>(Func<IDbConnection, Task<T>> func)
        {
            using (_connection)
            {
                _connection.Open();
                return await func.Invoke(_connection);
            }
        }

        public Task<T> WithConnectionAsync<T>(Func<IDbConnection, T> func)
        {
            using (_connection)
            {
                _connection.Open();
                return Task.FromResult(func.Invoke(_connection));
            }
        }
    }
}