namespace AspNet.Identity.Dapper.Repository.SqlServer
{
    public class SqlServerQuery : IIdentityDapperQueryProvider
    {
        private const string FindByNameAsync = "SELECT * FROM AspNetUsers WHERE UserName = @user";
        private const string FindUserById = "SELECT * FROM AspNetUsers WHERE Id = @id";
        //private const string UpdatePasswordHash  ="UPDATE AspNetUsers SET PasswordHash = @hash WHERE Id = @id";
        //private const string GetPasswordhash = "SELECT PasswordHash FROM AspNetUsers WHERE Id = @id";
        //private const string HasPasswordhash = "SELECT 1 FROM AspNetUsers WHERE Id = @id";
        //private const string SetSecurityStamp = "UPDATE AspNetUsers SET SecurityStamp = @securityStamp WHERE Id = @id";
        //private const string GetSecurityStamp = "SELECT TOP 1 SecurityStamp FROM AspNetUsers WHERE Id = @id";
        //private const string SetEmail = "UPDATE AspNetUsers SET Email = @mail WHERE Id = @id";
        //private const string GetEmail = "SELECT TOP 1 Email FROM AspNetUsers WHERE Id = @id";
        private const string FindUserByEmail = "SELECT TOP 1 * FROM AspNetUsers WHERE Email = @mail";
        //private const string SetEmailConfirmed = "UPDATE AspNetUsers SET EmailConfirmed = @confirm WHERE Id = @id";
        //private const string GetEmailConfirmed = "SELECT TOP 1 EmailConfirmed FROM AspNetUsers WHERE Id = @id";
        //private const string SetPhoneNumber = "UPDATE AspNetUsers SET PhoneNumber = @phone WHERE Id = @id";
        //private const string GetPhoneNumber = "SELECT PhoneNumber FROM AspNetUsers WHERE Id = @id";
        //private const string SetPhoneNumberConfirmed = "UPDATE AspNetUsers SET PhoneNumberConfirmed = @confirm WHERE Id = @id";
        //private const string GetPhoneNumberConfirmed = "SELECT TOP 1 PhoneNumberConfirmed FROM AspNetUsers WHERE Id = @id";
        //private const string SetTwoFactorEnabled = "UPDATE AspNetUsers SET TwoFactorEnabled = @twoFactor WHERE Id = @id";
        //private const string GetTwoFactorEnabled = "SELECT TOP 1 TwoFactorEnabled FROM AspNetUsers WHERE Id = @id";
        //private const string SetLockoutEndDate = "UPDATE AspNetUsers SET LockoutEndDateUtc = @lockout WHERE Id = @id";
        private const string GetLockoutEndDate = "SELECT TOP 1 LockoutEndDateUtc FROM AspNetUsers WHERE Id = @id";
        //private const string SetLockoutEnabled = "UPDATE AspNetUsers SET LockoutEnabled = @lockout WHERE Id = @id";
        //private const string IncrementAccessFailedCount = "UPDATE AspNetUsers SET AccessFailedCount = @failed WHERE Id = @id";

        private const string GetLoginsByUserIdAsync = "SELECT * FROM AspNetUserLogins WHERE UserId = @id";
        private const string FindUserLoginsAsync = "SELECT * FROM AspNetUserLogins WHERE LoginProvider = @provider AND ProviderKey= @key";
        private const string RemoveLoginAsync = "DELETE FROM AspNetUserLogins  WHERE LoginProvider = @provider AND ProviderKey = @key AND UserId = @userId";

        private const string GetUserClaimsByUserId = "SELECT * FROM AspNetUserClaims WHERE UserId = @id";
        private const string DeleteUserClaimsByUserAndClaims =
            "DELETE FROM AspNetUserClaims WHERE Id IN (SELECT Id FROM AspNetUserClaims WHERE UserId = @id AND ClaimValue = @claimValue AND ClaimType = @claimType)";

        private const string GetRoleIdFromRoleName = "SELECT Id FROM AspNetRoles WHERE Name = @name";
        private const string DeleteUserRole = "DELETE FROM AspNetUserRoles WHERE UserId = @userId AND RoleId = @roleId";

        private const string GetUserRoleByUserId =
            "SELECT r.name FROM AspNetUserRoles ur INNER JOIN AspNetRoles r ON ur.RoleId = r.Id WHERE ur.UserId = @userId";

        private const string IsUserInRole = "SELECT 1 FROM AspNetUserRoles ur INNER JOIN AspNetRoles r ON ur.RoleId = r.Id " +
                                            "WHERE ur.UserId = @userId AND r.name = @name";

        private const string FindRoleById = "SELECT TOP 1 * FROM AspNetRoles WHERE Id = @id";
        private const string FindRoleByName = "SELECT TOP 1 * FROM AspNetRoles WHERE Name = @name";


        public string FindByName { get { return FindByNameAsync; } }
        public string RemoveLogin { get { return RemoveLoginAsync; } }
        public string GetLogins {  get { return GetLoginsByUserIdAsync; } }
        public string FindIdentityUserLogin { get { return FindUserLoginsAsync; } }
        public string FindIdentityUserById { get { return FindUserById; } }
        public string GetClaimsAsync { get { return GetUserClaimsByUserId; } }
        public string RemoveClaimAsync { get { return DeleteUserClaimsByUserAndClaims; } }
        public string GetRoleIdByName { get {  return GetRoleIdFromRoleName;} }
        public string RemoveFromRole { get { return DeleteUserRole; } }
        public string GetRolesAsync { get { return GetUserRoleByUserId; } }
        public string IsInRoleAsync { get { return IsUserInRole; } }
        public string GetLockoutEndDateAsync { get { return GetLockoutEndDate; } }
        public string FindUserByEmailAsync { get { return FindUserByEmail; } }
        public string FindRoleByIdAsync { get { return FindRoleById;} }
        public string FindRoleByNameAsync { get { return FindRoleByName; } }
        //public string SetPasswordHashAsync { get { return UpdatePasswordHash; } }
        //public string GetPasswordHashAsync { get { return GetPasswordhash; } }
        //public string HasPasswordHashAsync { get { return HasPasswordhash; } }
        //public string SetSecurityStampAsync { get { return SetSecurityStamp; } }
        //public string GetSecurityStampAsync { get { return GetSecurityStamp; } }
        //public string SetEmailAsync { get { return SetEmail; } }
        //public string GetEmailAsync { get { return GetEmail; } }

        //public string SetEmailConfirmedAsync { get { return SetEmailConfirmed; } }
        //public string GetEmailConfirmedAsync { get { return GetEmailConfirmed; } }
        //public string SetPhoneNumberAsync { get { return SetPhoneNumber; } }
        //public string GetPhoneNumberAsync { get { return GetPhoneNumber; } }
        //public string SetPhoneNumberConfirmedAsync { get { return SetPhoneNumberConfirmed; } }
        //public string GetPhoneNumberConfirmedAsync { get { return GetPhoneNumberConfirmed; } }
        //public string SetTwoFactorEnabledAsync { get { return SetTwoFactorEnabled; } }
        //public string GetTwoFactorEnabledAsync { get{ return GetTwoFactorEnabled; } }

        //public string SetLockoutEndDateAsync { get{ return SetLockoutEndDate; } }
        //public string SetLockoutEnabledAsync { get { return SetLockoutEnabled; } }
        //public string IncrementAccessFailedCountAsync { get { return IncrementAccessFailedCount; } }
    }

    public interface IIdentityDapperQueryProvider
    {
        string FindByName { get; }
        string RemoveLogin { get; }
        string GetLogins { get; }
        string FindIdentityUserLogin { get; }
        string FindIdentityUserById { get; }
        string GetClaimsAsync { get; }
        string RemoveClaimAsync { get; }
        string GetRoleIdByName { get; }
        string RemoveFromRole { get; }
        string GetRolesAsync { get; }
        string IsInRoleAsync { get; }
        string FindRoleByIdAsync { get; }
        string FindRoleByNameAsync { get; }
        //string SetPasswordHashAsync { get; }
        //string GetPasswordHashAsync { get; }
        //string HasPasswordHashAsync { get; }
        //string SetSecurityStampAsync { get; }
        //string GetSecurityStampAsync { get; }
        //string SetEmailAsync { get; }
        //string GetEmailAsync { get; }
        string FindUserByEmailAsync { get; }
        //string SetEmailConfirmedAsync { get; }
        //string GetEmailConfirmedAsync { get; }

        //string SetPhoneNumberAsync { get; }
        //string GetPhoneNumberAsync { get; }
        //string SetPhoneNumberConfirmedAsync { get; }
        //string GetPhoneNumberConfirmedAsync { get; }
        //string SetTwoFactorEnabledAsync { get; }
        //string GetTwoFactorEnabledAsync { get; }
        string GetLockoutEndDateAsync { get; }
        //string SetLockoutEndDateAsync { get; }
        //string SetLockoutEnabledAsync { get; }
        //string IncrementAccessFailedCountAsync { get; }
    }
}