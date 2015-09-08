using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Dapper.Contrib.Extensions
{
    internal static class BaseDialectProvider
    {
        internal const string InsertQuery = "INSERT INTO {0} ({1}) VALUES ({2})";

        private static readonly List<Type> UnQuoteList = new List<Type>
        {
            typeof (bool),
            typeof (bool?),
            typeof (byte),
            typeof (byte?),
            typeof (sbyte),
            typeof (sbyte?),
            typeof (short),
            typeof (short?),
            typeof (ushort),
            typeof (ushort?),
            typeof (int),
            typeof (int?),
            typeof (uint),
            typeof (uint?),
            typeof (long),
            typeof (long?),
            typeof (ulong),
            typeof (ulong?),
            typeof (float),
            typeof (float?),
            typeof (double),
            typeof (double?),
            typeof (decimal),
            typeof (decimal?),
        };

        public static string GetQuotedParam(string paramValue)
        {
            return "'" + paramValue.Replace("'", "''") + "'";
        }

        public static string GetQuotedValue(object value, Type fieldType, ISqlAdapter adapter)
        {
            if (value == null) return "NULL";

            if (fieldType == typeof(float))
                return ((float)value).ToString(CultureInfo.InvariantCulture);

            if (fieldType == typeof(double))
                return ((double)value).ToString(CultureInfo.InvariantCulture);

            if (fieldType == typeof(decimal))
                return ((decimal)value).ToString(CultureInfo.InvariantCulture);

            return ShouldQuoteValue(fieldType)
                    ? adapter.GetQuotedParam(value.ToString())
                    : value.ToString();
        }

        public static string GetQuotedColumnName(string columnName)
        {
            return string.Format("\"{0}\"", columnName);
        }

        private static bool ShouldQuoteValue(Type type)
        {
            return UnQuoteList.All(ty => ty != type);
        }
    }
}