using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SqlExtensions.Tests
{
    class Program
    {
        private const string ConnectionString =
            "data source=localhost;initial catalog=dapper;user id=sa;password=rootcoop;";

        static void Main(string[] args)
        {
            //CleanUpTests();
            Setup();
            RunTests();
            CleanUpTests();
            Setup();
            RunAsyncTests();
            CleanUpTests();

            Console.WriteLine("Press any key...");
            Console.ReadKey();
        }

        private static void Setup()
        {

            const string theCommand =
                    @"create table Stuff (TheId int IDENTITY(1,1) not null, Name nvarchar(100) not null, Created DateTime null); 
                      create table People (Id int IDENTITY(1,1) not null, Name nvarchar(100) not null);
                      create table Users (Id int IDENTITY(1,1) not null, Name nvarchar(100) not null, Age int not null);
                      create table Automobiles (Id int IDENTITY(1,1) not null, Name nvarchar(100) not null);
                      create table Results (Id int IDENTITY(1,1) not null, Name nvarchar(100) not null, [Order] int not null);";


            using (var connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                var sqlComm = new SqlCommand(theCommand) { Connection = connection };
                sqlComm.ExecuteNonQuery();
            }

            Console.WriteLine("Created database");
        }

        private static void RunTests()
        {
            var tester = new Tests();
            foreach (var method in typeof(Tests).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                Console.Write("Running " + method.Name);
                method.Invoke(tester, null);
                Console.WriteLine(" - OK!");
            }
        }

        private static void CleanUpTests()
        {
            const string theCommand =
                    @"Drop table Stuff; 
                     Drop table Users;
                     Drop table People;
                     Drop table Automobiles;
                     Drop table Results;";

            using (var connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                var sqlComm = new SqlCommand(theCommand) {Connection = connection};
                sqlComm.ExecuteNonQuery();
            }

            Console.WriteLine("Clean Up database");
        }

        private static void RunAsyncTests()
        {
            var tester = new TestsAsync();
            foreach (var method in typeof(TestsAsync).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                Console.Write("Running " + method.Name);
                Task.WaitAll((Task)method.Invoke(tester, null));
                Console.WriteLine(" - OK!");
            }
        }
    }
}
