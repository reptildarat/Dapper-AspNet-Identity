namespace Dapper.Contrib.Extensions
{
    public interface IReadDialectProvider
    {
        string LastInsertIdQuery { get; }
    }
}