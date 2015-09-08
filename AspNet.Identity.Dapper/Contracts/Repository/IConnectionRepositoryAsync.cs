using System;
using System.Data;
using System.Threading.Tasks;

namespace AspNet.Identity.Dapper.Contracts.Repository
{
    public interface IConnectionRepositoryAsync
    {
        Task WithTransactionAsync(Func<IDbConnection, Task> actions);
        Task<T> WithConnectionAsync<T>(Func<IDbConnection, Task<T>> func);
        Task<T> WithConnectionAsync<T>(Func<IDbConnection, T> func);
    }
}