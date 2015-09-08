using System.Configuration;
using AspNet.Identity.Dapper.Repository;
using AspNet.Identity.Dapper.Repository.SqlServer;

namespace AspNet.Identity.Dapper.Console
{
    class Program
    {
        
        static void Main(string[] args)
        {
            var connection = ConfigurationManager.ConnectionStrings["SqlServerConnection"].ConnectionString;
            var repo = new UserStore<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
                (new SqlServerConnection(connection));

            var data = repo.FindByIdAsync("806ac64c-6606-4309-b9b6-3a86481aeefd");
            
            System.Console.WriteLine(data.Result.UserName);

            System.Console.ReadLine();
        }
    }
}
