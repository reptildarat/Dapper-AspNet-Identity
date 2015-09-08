using System;

namespace Dapper.Contrib.Extensions
{
    public interface IDialectProvider
    {
        string GetQuotedParam(string paramValue);
        string GetQuotedValue(object value, Type fieldType);
        string GetQuoteColumnName(string columnName);
    }
}