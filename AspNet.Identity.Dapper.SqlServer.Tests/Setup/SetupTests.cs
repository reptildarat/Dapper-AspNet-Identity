using System.Configuration;
using System.Data;
using ServiceStack.OrmLite;

namespace AspNet.Identity.Dapper.SqlServer.Tests.Setup
{
    public static class SetupTests
    {
        public static string ConnectionString = ConfigurationManager.ConnectionStrings["SqlServerConnection"].ConnectionString;
        public static OrmLiteConnectionFactory Connection()
        {       
            return new OrmLiteConnectionFactory(ConnectionString, SqlServerDialect.Provider);
        }



        public static void SetupDatabase()
        {
            using (var conn = Connection().OpenDbConnection())
            {
                RecreateTables(conn);
            }
        }

        public static void CreateTable()
        {
            using (var conn = Connection().OpenDbConnection())
            {
                conn.CreateTable<Extend.IdentityUser<string>>();
                conn.CreateTable<Extend.IdentityRole<string>>();
                conn.CreateTable<Extend.IdentityUserRole<string>>();
                conn.CreateTable<Extend.IdentityUserLogin<string>>();
                conn.CreateTable<Extend.IdentityUserClaim<string>>();
            }
           
        }

        private static void RecreateTables(IDbConnection db)
        {
            DeleteData();
        }

        public static void DeleteData()
        {
            using (var db = Connection().OpenDbConnection())
            {
                db.DeleteAll<Extend.IdentityUserRole<string>>();
                db.DeleteAll<Extend.IdentityUserLogin<string>>();
                db.DeleteAll<Extend.IdentityUserClaim<string>>();
                db.DeleteAll<Extend.IdentityUser<string>>();
                db.DeleteAll<Extend.IdentityRole<string>>();
            }

        }

        public static void DropTables(IDbConnection db)
        {
            db.DropTable<Extend.IdentityUserRole<string>>();
            db.DropTable<Extend.IdentityUserLogin<string>>();
            db.DropTable<Extend.IdentityUserClaim<string>>();
            db.DropTable<Extend.IdentityUser<string>>();
            db.DropTable<Extend.IdentityRole<string>>();

        }
    }
}