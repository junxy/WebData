using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Web;
using System.Web.Routing;
using System.Web.Security;
//using System.Web.WebPages;
using WebMatrix.WebData.Resources;

namespace WebMatrix.WebData {
    public static class WebSecurity {
        public static readonly string EnableSimpleMembershipKey = "enableSimpleMembership";

        public static int CurrentUserId {
            get {
                return GetUserId(CurrentUserName);
            }
        }

        public static string CurrentUserName {
            get {
                return Context.User.Identity.Name;
            }
        }

        public static bool HasUserId {
            get {
                return CurrentUserId != -1;
            }
        }

        public static bool IsAuthenticated {
            get {
                return Request.IsAuthenticated;
            }
        }

        internal static HttpContextBase Context {
            get {
                return new HttpContextWrapper(HttpContext.Current);
            }
        }

        internal static HttpRequestBase Request {
            get {
                return Context.Request;
            }
        }

        internal static HttpResponseBase Response {
            get {
                return Context.Response;
            }
        }

        internal static void PreAppStartInit() {
            // Allow use of <add key="EnableSimpleMembershipKey" value="false" /> to disable registration of membership/role providers as default.
            if (ConfigUtil.SimpleMembershipEnabled) {
                // called during PreAppStart, should also hook up the config for MembershipProviders?
                // Replace the AspNetSqlMembershipProvider (which is the default that is registered in root web.config)
                const string builtInMembershipProviderName = "AspNetSqlMembershipProvider";
                var builtInMembership = Membership.Providers[builtInMembershipProviderName];
                if (builtInMembership != null) {
                    var sMembership = CreateDefaultSimpleMembershipProvider(builtInMembershipProviderName, currentDefault: builtInMembership);
                    Membership.Providers.Remove(builtInMembershipProviderName);
                    Membership.Providers.Add(sMembership);
                }

                Roles.Enabled = true;
                const string builtInRolesProviderName = "AspNetSqlRoleProvider";
                var builtInRoles = Roles.Providers[builtInRolesProviderName];
                if (builtInRoles != null) {
                    var sRoles = CreateDefaultSimpleRoleProvider(builtInRolesProviderName, currentDefault: builtInRoles);
                    Roles.Providers.Remove(builtInRolesProviderName);
                    Roles.Providers.Add(sRoles);
                }
            }
        }

        private static ExtendedMembershipProvider VerifyProvider() {
            ExtendedMembershipProvider provider = Membership.Provider as ExtendedMembershipProvider;
            if (provider == null) {
                throw new InvalidOperationException(WebDataResources.Security_NoExtendedMembershipProvider);
            }
            provider.VerifyInitialized(); // Have the provider verify that it's initialized (only our SimpleMembershipProvider does anything here)
            return provider;
        }

        public static void InitializeDatabaseConnection(string connectionStringName, string userTableName, string userIdColumn, string userNameColumn, bool autoCreateTables) {
            DatabaseConnectionInfo connect = new DatabaseConnectionInfo();
            connect.ConnectionStringName = connectionStringName;
            InitializeProviders(connect, userTableName, userIdColumn, userNameColumn, autoCreateTables);
        }

        public static void InitializeDatabaseConnection(string connectionString, string providerName, string userTableName, string userIdColumn, string userNameColumn, bool autoCreateTables) {
            DatabaseConnectionInfo connect = new DatabaseConnectionInfo();
            connect.ConnectionString = connectionString;
            connect.ProviderName = providerName;
            InitializeProviders(connect, userTableName, userIdColumn, userNameColumn, autoCreateTables);
        }

        private static void InitializeProviders(DatabaseConnectionInfo connect, string userTableName, string userIdColumn, string userNameColumn, bool autoCreateTables) {
            SimpleMembershipProvider sMembership = Membership.Provider as SimpleMembershipProvider;
            if (sMembership != null) {
                InitializeMembershipProvider(sMembership, connect, userTableName, userIdColumn, userNameColumn, autoCreateTables);
            }

            SimpleRoleProvider sRoles = Roles.Provider as SimpleRoleProvider;
            if (sRoles != null) {
                InitializeRoleProvider(sRoles, connect, userTableName, userIdColumn, userNameColumn, autoCreateTables);
            }
        }

        internal static void InitializeMembershipProvider(SimpleMembershipProvider sMembership, DatabaseConnectionInfo connect, string userTableName, string userIdColumn, string userNameColumn, bool createTables) {
            if (sMembership.InitializeCalled) {
                throw new InvalidOperationException(WebDataResources.Security_InitializeAlreadyCalled);
            }
            sMembership.ConnectionInfo = connect;
            sMembership.UserIdColumn = userIdColumn;
            sMembership.UserNameColumn = userNameColumn;
            sMembership.UserTableName = userTableName;
            if (createTables) {
                sMembership.CreateTablesIfNeeded();
            }
            else {
                // We want to validate the user table if we aren't creating them
                sMembership.ValidateUserTable();
            }
            sMembership.InitializeCalled = true;
        }

        internal static void InitializeRoleProvider(SimpleRoleProvider sRoles, DatabaseConnectionInfo connect, string userTableName, string userIdColumn, string userNameColumn, bool createTables) {
            if (sRoles.InitializeCalled) {
                throw new InvalidOperationException(WebDataResources.Security_InitializeAlreadyCalled);
            }
            sRoles.ConnectionInfo = connect;
            sRoles.UserTableName = userTableName;
            sRoles.UserIdColumn = userIdColumn;
            sRoles.UserNameColumn = userNameColumn;
            if (createTables) {
                sRoles.CreateTablesIfNeeded();
            }
            sRoles.InitializeCalled = true;
        }

        private static SimpleMembershipProvider CreateDefaultSimpleMembershipProvider(string name, MembershipProvider currentDefault) {
            var membership = new SimpleMembershipProvider(previousProvider: currentDefault);
            NameValueCollection config = new NameValueCollection();
            membership.Initialize(name, config);
            return membership;
        }

        private static SimpleRoleProvider CreateDefaultSimpleRoleProvider(string name, RoleProvider currentDefault) {
            var roleProvider = new SimpleRoleProvider(previousProvider: currentDefault);
            NameValueCollection config = new NameValueCollection();
            roleProvider.Initialize(name, config);
            return roleProvider;
        }

        [SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Login", Justification = "Login is used more consistently in ASP.Net")]
        [SuppressMessage("Microsoft.Design", "CA1026:DefaultParametersShouldNotBeUsed", Justification = "This is a helper class, and we are not removing optional parameters from methods in helper classes")]
        public static bool Login(string userName, string password, bool persistCookie = false) {
            VerifyProvider();
            bool success = Membership.ValidateUser(userName, password);
            if (success) {
                FormsAuthentication.SetAuthCookie(userName, persistCookie);
            }
            return success;
        }

        [SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout", Justification = "Login is used more consistently in ASP.Net")]
        public static void Logout() {
            VerifyProvider();
            FormsAuthentication.SignOut();
        }

        public static bool ChangePassword(string userName, string currentPassword, string newPassword) {
            VerifyProvider();
            bool success = false;
            try {
                var currentUser = Membership.GetUser(userName, true /* userIsOnline */);
                success = currentUser.ChangePassword(currentPassword, newPassword);
            }
            catch (ArgumentException) {
                // An argument exception is thrown if the new password does not meet the provider's requirements
            }

            return success;
        }

        public static bool ConfirmAccount(string accountConfirmationToken) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this
            return provider.ConfirmAccount(accountConfirmationToken);
        }

        [SuppressMessage("Microsoft.Design", "CA1026:DefaultParametersShouldNotBeUsed", Justification = "This is a helper class, and we are not removing optional parameters from methods in helper classes")]
        public static string CreateAccount(string userName, string password, bool requireConfirmationToken = false) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this

            return provider.CreateAccount(userName, password, requireConfirmationToken);
        }

        [SuppressMessage("Microsoft.Design", "CA1026:DefaultParametersShouldNotBeUsed", Justification = "This is a helper class, and we are not removing optional parameters from methods in helper classes")]
        public static string CreateUserAndAccount(string userName, string password, object propertyValues = null, bool requireConfirmationToken = false) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this

            IDictionary<string, object> values = null;
            if (propertyValues != null) {
                values = new RouteValueDictionary(propertyValues);
            }

            return provider.CreateUserAndAccount(userName, password, requireConfirmationToken, values);
        }

        [SuppressMessage("Microsoft.Design", "CA1026:DefaultParametersShouldNotBeUsed", Justification = "This is a helper class, and we are not removing optional parameters from methods in helper classes")]
        public static string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow = 1440) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this

            return provider.GeneratePasswordResetToken(userName, tokenExpirationInMinutesFromNow);
        }

        public static bool UserExists(string userName) {
            VerifyProvider();
            return Membership.GetUser(userName) != null;
        }

        public static int GetUserId(string userName) {
            VerifyProvider();
            MembershipUser user = Membership.GetUser(userName);
            if (user == null) {
                return -1;
            }

            // REVIEW: This cast is breaking the abstraction for the membershipprovider, we basically assume that userids are ints
            return (int)user.ProviderUserKey;
        }

        public static int GetUserIdFromPasswordResetToken(string token) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this

            return provider.GetUserIdFromPasswordResetToken(token);
        }

        public static bool IsCurrentUser(string userName) {
            VerifyProvider();
            return String.Equals(CurrentUserName, userName, StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsConfirmed(string userName) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this

            return provider.IsConfirmed(userName);
        }

        // Make sure the logged on user is same as the one specified by the id
        private static bool IsUserLoggedOn(int userId) {
            VerifyProvider();
            return CurrentUserId == userId;
        }

        // Make sure the user was authenticated
        public static void RequireAuthenticatedUser() {
            VerifyProvider();
            var user = Context.User;
            if (user == null || !user.Identity.IsAuthenticated) {
                Response.SetStatus(HttpStatusCode.Unauthorized);
            }
        }

        // Make sure the user was authenticated
        public static void RequireUser(int userId) {
            VerifyProvider();
            if (!IsUserLoggedOn(userId)) {
                Response.SetStatus(HttpStatusCode.Unauthorized);
            }
        }

        public static void RequireUser(string userName) {
            VerifyProvider();
            if (!string.Equals(CurrentUserName, userName, StringComparison.OrdinalIgnoreCase)) {
                Response.SetStatus(HttpStatusCode.Unauthorized);
            }
        }

        public static void RequireRoles(params string[] roles) {
            VerifyProvider();
            foreach (string role in roles) {
                if (!Roles.IsUserInRole(CurrentUserName, role)) {
                    Response.SetStatus(HttpStatusCode.Unauthorized);
                    return;
                }
            }
        }

        public static bool ResetPassword(string passwordResetToken, string newPassword) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this
            return provider.ResetPasswordWithToken(passwordResetToken, newPassword);
        }

        public static bool IsAccountLockedOut(string userName, int allowedPasswordAttempts, int intervalInSeconds) {
            VerifyProvider();
            return IsAccountLockedOut(userName, allowedPasswordAttempts, TimeSpan.FromSeconds(intervalInSeconds));
        }

        public static bool IsAccountLockedOut(string userName, int allowedPasswordAttempts, TimeSpan interval) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this

            return IsAccountLockedOutInternal(provider, userName, allowedPasswordAttempts, interval);
        }

        internal static bool IsAccountLockedOutInternal(ExtendedMembershipProvider provider, string userName, int allowedPasswordAttempts, TimeSpan interval) {
            return (provider.GetUser(userName, false) != null &&
                     provider.GetPasswordFailuresSinceLastSuccess(userName) > allowedPasswordAttempts &&
                     provider.GetLastPasswordFailureDate(userName).Add(interval) > DateTime.UtcNow);
        }

        public static int GetPasswordFailuresSinceLastSuccess(string userName) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this
            
            return provider.GetPasswordFailuresSinceLastSuccess(userName);
        }

        public static DateTime GetCreateDate(string userName) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this
            
            return provider.GetCreateDate(userName);
        }

        public static DateTime GetPasswordChangedDate(string userName) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this
            
            return provider.GetPasswordChangedDate(userName);
        }

        public static DateTime GetLastPasswordFailureDate(string userName) {
            ExtendedMembershipProvider provider = VerifyProvider();
            Debug.Assert(provider != null); // VerifyProvider checks this
            
            return provider.GetLastPasswordFailureDate(userName);
        }

    }
}
