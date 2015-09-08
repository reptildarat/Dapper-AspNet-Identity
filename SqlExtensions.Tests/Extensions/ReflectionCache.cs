using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Dapper.Contrib.Extensions
{
    public static partial class SqlMapperExtensions
    {
        private static readonly ConcurrentDictionary<RuntimeTypeHandle, List<PropertyInfo>> KeyProperties = new ConcurrentDictionary<RuntimeTypeHandle, List<PropertyInfo>>();
        private static readonly ConcurrentDictionary<RuntimeTypeHandle, List<PropertyInfo>> TypeProperties = new ConcurrentDictionary<RuntimeTypeHandle, List<PropertyInfo>>();
        private static readonly ConcurrentDictionary<RuntimeTypeHandle, List<PropertyInfo>> ComputedProperties = new ConcurrentDictionary<RuntimeTypeHandle, List<PropertyInfo>>();
        private static readonly ConcurrentDictionary<RuntimeTypeHandle, List<PropertyInfo>> WithoutKeyComputedProperties = new ConcurrentDictionary<RuntimeTypeHandle, List<PropertyInfo>>();

        private static List<PropertyInfo> ComputedPropertiesCache(Type type)
        {
            List<PropertyInfo> pi;
            if (ComputedProperties.TryGetValue(type.TypeHandle, out pi))
            {
                return pi;
            }

            var computedProperties = TypePropertiesCache(type)
                .Where(p => p.GetCustomAttributes(true).Any(a => a is ComputedAttribute)).ToList();

            ComputedProperties[type.TypeHandle] = computedProperties;
            return computedProperties;
        }

        private static List<PropertyInfo> KeyPropertiesCache(Type type)
        {

            List<PropertyInfo> pi;
            if (KeyProperties.TryGetValue(type.TypeHandle, out pi))
            {
                return pi;
            }

            var allProperties = TypePropertiesCache(type);
            var keyProperties = allProperties.Where(p => p.GetCustomAttributes(true).Any(a => a is KeyAttribute)).ToList();

            if (keyProperties.Count == 0)
            {
                var idProp = allProperties.FirstOrDefault(p => p.Name.ToLower() == "id");
                if (idProp != null)
                {
                    keyProperties.Add(idProp);
                }
            }

            KeyProperties[type.TypeHandle] = keyProperties;
            return keyProperties;
        }

        private static List<PropertyInfo> TypePropertiesCache(Type type)
        {
            List<PropertyInfo> pis;
            if (TypeProperties.TryGetValue(type.TypeHandle, out pis))
            {
                return pis;
            }

            var properties = type.GetProperties().Where(IsWriteable).ToList();
            TypeProperties[type.TypeHandle] = properties;
            return properties;
        }

        private static List<PropertyInfo> AllPropertiesExceptKeyAndComputed(Type type)
        {
            List<PropertyInfo> key;
            if (WithoutKeyComputedProperties.TryGetValue(type.TypeHandle, out key))
            {
                return key;
            }

            var allProperties = TypePropertiesCache(type);
            var keyProperties = KeyPropertiesCache(type);
            var computedProperties = ComputedPropertiesCache(type);

            var allPropertiesExceptKeyAndComputed =
                allProperties.Except(keyProperties.Union(computedProperties)).ToList();

            WithoutKeyComputedProperties[type.TypeHandle] = allPropertiesExceptKeyAndComputed;
            return allPropertiesExceptKeyAndComputed;
        }

        public static bool IsWriteable(PropertyInfo pi)
        {
            object[] attributes = pi.GetCustomAttributes(typeof(WriteAttribute), false);
            if (attributes.Length != 1) return true;
            var write = (WriteAttribute)attributes[0];
            return write.Write;
        }
    }
}