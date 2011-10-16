//------------------------------------------------------------------------------
// <copyright file="CompactMembershipProvider.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace WebMatrix.WebData {
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Configuration.Provider;
    using System.Globalization;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    //using System.Web.Helpers;
    using System.Web.Security;
    using System.Web.WebPages;
    using Microsoft.Internal.Web.Utils;
    using WebMatrix.Data;
    using WebMatrix.WebData.Resources;

    public class SimpleMembershipProvider : ExtendedMembershipProvider {
        private const int TOKEN_SIZE_IN_BYTES = 16;

        private MembershipProvider _previousProvider;

        public SimpleMembershipProvider() : this(null) { }
        public SimpleMembershipProvider(MembershipProvider previousProvider) {
            _previousProvider = previousProvider;
            if (_previousProvider != null) {
                _previousProvider.ValidatingPassword += (sender, args) => {
                    if (!InitializeCalled) {
                        OnValidatingPassword(args);
                    }
                };
            }
        }


        private MembershipProvider PreviousProvider {
            get {
                if (_previousProvider == null) {
                    throw new InvalidOperationException(WebDataResources.Security_InitializeMustBeCalledFirst);
                }
                else {
                    return _previousProvider;
                }
            }
        }

        // Public properties
        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool EnablePasswordRetrieval {
            get {
                return InitializeCalled ? false : PreviousProvider.EnablePasswordRetrieval;
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool EnablePasswordReset {
            get {
                return InitializeCalled ? false : PreviousProvider.EnablePasswordReset;
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool RequiresQuestionAndAnswer {
            get { return InitializeCalled ? false : PreviousProvider.RequiresQuestionAndAnswer; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool RequiresUniqueEmail {
            get { return InitializeCalled ? false : PreviousProvider.RequiresUniqueEmail; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipPasswordFormat PasswordFormat {
            get { return InitializeCalled ? MembershipPasswordFormat.Hashed : PreviousProvider.PasswordFormat; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int MaxInvalidPasswordAttempts {
            get { return InitializeCalled ? int.MaxValue : PreviousProvider.MaxInvalidPasswordAttempts; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int PasswordAttemptWindow {
            get { return InitializeCalled ? int.MaxValue : PreviousProvider.PasswordAttemptWindow; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int MinRequiredPasswordLength {
            get { return InitializeCalled ? 0 : PreviousProvider.MinRequiredPasswordLength; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int MinRequiredNonAlphanumericCharacters {
            get { return InitializeCalled ? 0 : PreviousProvider.MinRequiredNonAlphanumericCharacters; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string PasswordStrengthRegularExpression {
            get { return InitializeCalled ? "" : PreviousProvider.PasswordStrengthRegularExpression; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string ApplicationName {
            get {
                if (InitializeCalled) {
                    throw new NotSupportedException();
                }
                else {
                    return PreviousProvider.ApplicationName;
                }

            }
            set {
                if (InitializeCalled) {
                    throw new NotSupportedException();
                }
                else {
                    PreviousProvider.ApplicationName = value;
                }
            }
        }

        static internal string MembershipTableName {
            get {
                return "webpages_Membership";
            }
        }

        private string SafeUserTableName {
            get {
                return "[" + UserTableName + "]";
            }
        }

        private string SafeUserIdColumn {
            get {
                return "[" + UserIdColumn + "]";
            }
        }

        private string SafeUserNameColumn {
            get {
                return "[" + UserNameColumn + "]";
            }
        }

        // represents the User table for the app
        public string UserTableName { get; set; }

        // represents the User created UserName column, i.e. Email
        public string UserNameColumn { get; set; }

        // Represents the User created id column, i.e. ID;
        // REVIEW: we could get this from the primary key of UserTable in the future
        public string UserIdColumn { get; set; }

        internal DatabaseConnectionInfo ConnectionInfo { get; set; }
        internal bool InitializeCalled { get; set; }

        internal override void VerifyInitialized() {
            if (!InitializeCalled) {
                throw new InvalidOperationException(WebDataResources.Security_InitializeMustBeCalledFirst);
            }
        }

        // Inherited from ProviderBase - The "previous provider" we get has already been initialized by the Config system,
        // so we shouldn't forward this call
        public override void Initialize(string name, NameValueCollection config) {
            if (config == null)
                throw new ArgumentNullException("config");
            if (String.IsNullOrEmpty(name))
                name = "SimpleMembershipProvider";
            if (string.IsNullOrEmpty(config["description"])) {
                config.Remove("description");
                config.Add("description", "Simple Membership Provider");
            }
            base.Initialize(name, config);

            config.Remove("connectionStringName");
            config.Remove("enablePasswordRetrieval");
            config.Remove("enablePasswordReset");
            config.Remove("requiresQuestionAndAnswer");
            config.Remove("applicationName");
            config.Remove("requiresUniqueEmail");
            config.Remove("maxInvalidPasswordAttempts");
            config.Remove("passwordAttemptWindow");
            config.Remove("passwordFormat");
            config.Remove("name");
            config.Remove("description");
            config.Remove("minRequiredPasswordLength");
            config.Remove("minRequiredNonalphanumericCharacters");
            config.Remove("passwordStrengthRegularExpression");
            config.Remove("hashAlgorithmType");
            if (config.Count > 0) {
                string attribUnrecognized = config.GetKey(0);
                if (!String.IsNullOrEmpty(attribUnrecognized))
                    throw new ProviderException("Provider unrecognized attribute: " + attribUnrecognized);
            }
        }

        internal static bool CheckTableExists(Database db, string tableName) {
            var query = db.QuerySingle(@"SELECT * from INFORMATION_SCHEMA.TABLES where TABLE_NAME = @0", tableName);
            return query != null;
        }

        internal void CreateTablesIfNeeded() {
            using (var db = ConnectToDatabase()) {
                if (!CheckTableExists(db, UserTableName)) {
                    db.Execute(@"CREATE TABLE " + SafeUserTableName + "(" + SafeUserIdColumn + " int NOT NULL PRIMARY KEY IDENTITY, " + SafeUserNameColumn + " nvarchar(56) NOT NULL UNIQUE)");
                }

                if (!CheckTableExists(db, MembershipTableName)) {
                    db.Execute(@"CREATE TABLE " + MembershipTableName + @" (
                        UserId                                  int                 NOT NULL PRIMARY KEY,
                        CreateDate                              datetime            ,
                        ConfirmationToken                       nvarchar(128)       ,
                        IsConfirmed                             bit                 DEFAULT 0,
                        LastPasswordFailureDate                 datetime            ,
                        PasswordFailuresSinceLastSuccess         int                 NOT NULL DEFAULT 0,
                        Password                                nvarchar(128)       NOT NULL,
                        PasswordChangedDate                     datetime            ,
                        PasswordSalt                            nvarchar(128)       NOT NULL,
                        PasswordVerificationToken               nvarchar(128)       ,
                        PasswordVerificationTokenExpirationDate datetime)");
                    // TODO: Do we want to add FK constraint to user table too?
                    //                        CONSTRAINT fk_UserId FOREIGN KEY (UserId) REFERENCES "+UserTableName+"("+UserIdColumn+"))");
                }
            }
        }

        // Not an override ==> Simple Membership MUST be enabled to use this method
        public int GetUserId(string userName) {
            VerifyInitialized();
            using (var db = ConnectToDatabase()) {
                return GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, userName);
            }
        }

        internal static int GetUserId(Database db, string userTableName, string userNameColumn, string userIdColumn, string userName) {
            var result = db.QueryValue(@"SELECT " + userIdColumn + " FROM " + userTableName + " WHERE (UPPER(" + userNameColumn + ") = @0)", userName.ToUpperInvariant());
            if (result != null) {
                return (int)result;
            }
            return -1;
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override int GetUserIdFromPasswordResetToken(string token) {
            VerifyInitialized();
            using (var db = ConnectToDatabase()) {
                var result = db.QuerySingle(@"SELECT UserId FROM " + MembershipTableName + " WHERE (PasswordVerificationToken = @0)", token);
                if (result != null && result[0] != null) {
                    return (int)result[0];
                }
                return -1;
            }
        }


        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer) {
            if (!InitializeCalled) {
                return PreviousProvider.ChangePasswordQuestionAndAnswer(username, password, newPasswordQuestion, newPasswordAnswer);
            }
            throw new NotSupportedException();
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override bool ConfirmAccount(string accountConfirmationToken) {
            VerifyInitialized();
            using (var db = ConnectToDatabase()) {
                int rows = db.Execute(@"UPDATE " + MembershipTableName + " SET IsConfirmed = 1 WHERE (ConfirmationToken = @0)", accountConfirmationToken);
                return rows > 0;
            }
        }

        private Database ConnectToDatabase() {
            return ConnectionInfo.Connect();
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override string CreateAccount(string userName, string password, bool requireConfirmationToken) {
            VerifyInitialized();

            if (password.IsEmpty()) {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);
            }

            string hashedPassword = Crypto.HashPassword(password);
            if (hashedPassword.Length > 128) {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);
            }

            if (userName.IsEmpty()) {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidUserName);
            }

            using (var db = ConnectToDatabase()) {
                // Step 1: Check if the user exists in the Users table
                int uid = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, userName);
                if (uid == -1) { // User not found
                    throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
                }

                // Step 2: Check if the user exists in the Membership table: Error if yes.
                var result = db.QuerySingle(@"SELECT COUNT(*) FROM [" + MembershipTableName + "] WHERE UserId = @0", uid);
                if (result[0] > 0) {
                    throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);
                }

                // Step 3: Create user in Membership table
                string token = null;
                object dbtoken = DBNull.Value;
                if (requireConfirmationToken) {
                    token = GenerateToken();
                    dbtoken = token;
                }
                int defaultNumPasswordFailures = 0;

                int insert = db.Execute(@"INSERT INTO [" + MembershipTableName + "] (UserId, [Password], PasswordSalt, IsConfirmed, ConfirmationToken, CreateDate, PasswordChangedDate, PasswordFailuresSinceLastSuccess)"
                                      + " VALUES (@0, @1, @2, @3, @4, @5, @5, @6)", uid, hashedPassword, String.Empty /* salt column is unused */, !requireConfirmationToken, dbtoken, DateTime.UtcNow, defaultNumPasswordFailures);
                if (insert != 1) {
                    throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
                }
                return token;
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status) {
            if (!InitializeCalled) {
                return PreviousProvider.CreateUser(username, password, email, passwordQuestion, passwordAnswer, isApproved, providerUserKey, out status);
            }
            throw new NotSupportedException();
        }

        private void CreateUserRow(Database db, string userName, IDictionary<string, object> values) {
            // Make sure user doesn't exist
            int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, userName);
            if (userId != -1) {
                throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);
            }

            StringBuilder columnString = new StringBuilder();
            columnString.Append(SafeUserNameColumn);
            StringBuilder argsString = new StringBuilder();
            argsString.Append("@0");
            List<object> argsArray = new List<object>();
            argsArray.Add(userName);
            if (values != null) {
                int index = 1;
                foreach (string key in values.Keys) {
                    // Skip the user name column since we always generate that
                    if (String.Equals(UserNameColumn, key, StringComparison.OrdinalIgnoreCase)) continue;
                    columnString.Append(",").Append(key);
                    argsString.Append(",@").Append(index++);
                    object value = values[key];
                    if (value == null) {
                        value = DBNull.Value;
                    }
                    argsArray.Add(value);
                }
            }

            int rows = db.Execute("INSERT INTO " + SafeUserTableName + " (" + columnString.ToString() + ") VALUES (" + argsString.ToString() + ")", argsArray.ToArray());
            if (rows != 1) {
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values) {
            VerifyInitialized();

            using (var db = ConnectToDatabase()) {
                CreateUserRow(db, userName, values);
                return CreateAccount(userName, password, requireConfirmation);
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string GetPassword(string username, string answer) {
            if (!InitializeCalled) {
                return PreviousProvider.GetPassword(username, answer);
            }
            throw new NotSupportedException();
        }

        private static bool SetPassword(Database db, int userId, string newPassword) {
            string hashedPassword = Crypto.HashPassword(newPassword);
            if (hashedPassword.Length > 128)
                throw new ArgumentException(WebDataResources.SimpleMembership_PasswordTooLong);

            // Update new password
            int result = db.Execute(@"UPDATE " + MembershipTableName + " SET Password=@0, PasswordSalt=@1, PasswordChangedDate=@2 WHERE UserId = @3", hashedPassword, String.Empty /* salt column is unused */, DateTime.UtcNow, userId);
            return result > 0;
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool ChangePassword(string username, string oldPassword, string newPassword) {
            if (!InitializeCalled) {
                return PreviousProvider.ChangePassword(username, oldPassword, newPassword);
            }

            // REVIEW: are commas special in the password?
            if (username.IsEmpty()) throw ExceptionHelper.CreateArgumentNullOrEmptyException("username");
            if (oldPassword.IsEmpty()) throw ExceptionHelper.CreateArgumentNullOrEmptyException("oldPassword");
            if (newPassword.IsEmpty()) throw ExceptionHelper.CreateArgumentNullOrEmptyException("newPassword");

            using (var db = ConnectToDatabase()) {
                int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, username);
                if (userId == -1)
                    return false; // User not found

                // First check that the old credentials match
                if (!CheckPassword(db, userId, oldPassword)) {
                    return false;
                }

                return SetPassword(db, userId, newPassword);
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string ResetPassword(string username, string answer) {
            if (!InitializeCalled) {
                return PreviousProvider.ResetPassword(username, answer);
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline) {
            if (!InitializeCalled) {
                return PreviousProvider.GetUser(providerUserKey, userIsOnline);
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUser GetUser(string username, bool userIsOnline) {
            if (!InitializeCalled) {
                return PreviousProvider.GetUser(username, userIsOnline);
            }
            if (username.IsEmpty()) {
                ExceptionHelper.CreateArgumentNullOrEmptyException("username");
            }
            using (var db = ConnectToDatabase()) {
                int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, username);
                if (userId == -1)
                    return null; // User not found

                return new MembershipUser(Membership.Provider.Name, username, userId, null, null, null, true, false, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue);
            }

        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string GetUserNameByEmail(string email) {
            if (!InitializeCalled) {
                return PreviousProvider.GetUserNameByEmail(email);
            }
            throw new NotSupportedException();
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override bool DeleteAccount(string userName) {
            VerifyInitialized();
            if (userName.IsEmpty()) {
                ExceptionHelper.CreateArgumentNullOrEmptyException("userName");
            }
            using (var db = ConnectToDatabase()) {
                int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, userName);
                if (userId == -1)
                    return false; // User not found

                int deleted = db.Execute(@"DELETE FROM " + MembershipTableName + " WHERE UserId = @0", userId);
                return (deleted == 1);
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool DeleteUser(string username, bool deleteAllRelatedData) {
            if (!InitializeCalled) {
                return PreviousProvider.DeleteUser(username, deleteAllRelatedData);
            }
            if (username.IsEmpty()) {
                ExceptionHelper.CreateArgumentNullOrEmptyException("username");
            }
            using (var db = ConnectToDatabase()) {
                int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, username);
                if (userId == -1)
                    return false; // User not found

                int deleted = db.Execute(@"DELETE FROM " + SafeUserTableName + " WHERE " + SafeUserIdColumn + " = @0", userId);
                bool returnValue = (deleted == 1);

                //if (deleteAllRelatedData) {
                // REVIEW: do we really want to delete from the user table?
                //}
                return returnValue;
            }
        }

        internal bool DeleteUserAndAccountInternal(string userName) {
            return (DeleteAccount(userName) && DeleteUser(userName, false));
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords) {
            if (!InitializeCalled) {
                return PreviousProvider.GetAllUsers(pageIndex, pageSize, out totalRecords);
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int GetNumberOfUsersOnline() {
            if (!InitializeCalled) {
                return PreviousProvider.GetNumberOfUsersOnline();
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords) {
            if (!InitializeCalled) {
                return PreviousProvider.FindUsersByName(usernameToMatch, pageIndex, pageSize, out totalRecords);
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords) {
            if (!InitializeCalled) {
                return PreviousProvider.FindUsersByEmail(emailToMatch, pageIndex, pageSize, out totalRecords);
            }
            throw new NotSupportedException();
        }

        private static int GetPasswordFailuresSinceLastSuccess(Database db, int userId) {
            var failure = db.QueryValue(@"SELECT PasswordFailuresSinceLastSuccess FROM " + MembershipTableName + " WHERE (UserId = @0)", userId);
            if (failure != null) {
                return failure;
            }
            return -1;
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override int GetPasswordFailuresSinceLastSuccess(string userName) {
            using (var db = ConnectToDatabase()) {
                int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, userName);
                if (userId == -1)
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.Security_NoUserFound, userName));

                return GetPasswordFailuresSinceLastSuccess(db, userId);
            }
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override DateTime GetCreateDate(string userName) {
            using (var db = ConnectToDatabase()) {
                int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, userName);
                if (userId == -1)
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.Security_NoUserFound, userName));

                var createDate = db.QueryValue(@"SELECT CreateDate FROM " + MembershipTableName + " WHERE (UserId = @0)", userId);
                if (createDate != null) {
                    return createDate;
                }
                return DateTime.MinValue;
            }
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override DateTime GetPasswordChangedDate(string userName) {
            using (var db = ConnectToDatabase()) {
                int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, userName);
                if (userId == -1)
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.Security_NoUserFound, userName));

                var pwdChangeDate = db.QuerySingle(@"SELECT PasswordChangedDate FROM " + MembershipTableName + " WHERE (UserId = @0)", userId);
                if (pwdChangeDate != null && pwdChangeDate[0] != null) {
                    return (DateTime)pwdChangeDate[0];
                }
                return DateTime.MinValue;
            }
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override DateTime GetLastPasswordFailureDate(string userName) {
            using (var db = ConnectToDatabase()) {
                int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, userName);
                if (userId == -1)
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.Security_NoUserFound, userName));

                var failureDate = db.QuerySingle(@"SELECT LastPasswordFailureDate FROM " + MembershipTableName + " WHERE (UserId = @0)", userId);
                if (failureDate != null && failureDate[0] != null) {
                    return (DateTime)failureDate[0];
                }
                return DateTime.MinValue;
            }
        }


        private bool CheckPassword(Database db, int userId, string password) {
            string hashedPassword = GetHashedPassword(db, userId);
            bool verificationSucceeded = (hashedPassword != null && Crypto.VerifyHashedPassword(hashedPassword, password));
            if (verificationSucceeded) {
                // Reset password failure count on successful credential check
                db.Execute(@"UPDATE " + MembershipTableName + " SET PasswordFailuresSinceLastSuccess = 0 WHERE (UserId = @0)", userId);
            }
            else {
                int failures = GetPasswordFailuresSinceLastSuccess(db, userId);
                if (failures != -1) {
                    db.Execute(@"UPDATE " + MembershipTableName + " SET PasswordFailuresSinceLastSuccess = @1, LastPasswordFailureDate = @2 WHERE (UserId = @0)", userId, failures + 1, DateTime.UtcNow);
                }
            }
            return verificationSucceeded;
        }

        private string GetHashedPassword(Database db, int userId) {
            var pwdQuery = db.Query(@"SELECT m.[Password] " +
                                        @"FROM " + MembershipTableName + " m, " + SafeUserTableName + " u " +
                                        @"WHERE m.UserId = " + userId + " AND m.UserId = u." + SafeUserIdColumn).ToList();
            // REVIEW: Should get exactly one match, should we throw if we get > 1?
            if (pwdQuery.Count != 1) {
                return null;
            }
            return pwdQuery[0].Password;
        }

        // Ensures the user exists in the accounts table
        private int VerifyUserNameHasConfirmedAccount(Database db, string username, bool throwException) {
            int userId = GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, username);
            if (userId == -1) {
                if (throwException) {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.Security_NoUserFound, username));
                }
                else {
                    return -1;
                }
            }

            int result = db.QueryValue(@"SELECT COUNT(*) FROM " + MembershipTableName + " WHERE (UserId = @0 AND IsConfirmed = 1)", userId);
            if (result == 0) {
                if (throwException) {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.Security_NoAccountFound, username));
                }
                else {
                    return -1;
                }
            }
            return userId;
        }

        internal static string GenerateToken() {
            byte[] tokenBytes = new byte[TOKEN_SIZE_IN_BYTES];
            using (RNGCryptoServiceProvider prng = new RNGCryptoServiceProvider()) {
                prng.GetBytes(tokenBytes);
                return Convert.ToBase64String(tokenBytes);
            }
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow) {
            VerifyInitialized();
            if (userName.IsEmpty()) {
                throw ExceptionHelper.CreateArgumentNullOrEmptyException("username");
            }
            using (var db = ConnectToDatabase()) {
                int userId = VerifyUserNameHasConfirmedAccount(db, userName, throwException: true);

                string token = db.QueryValue(@"SELECT PasswordVerificationToken FROM " + MembershipTableName + " WHERE (UserId = @0 AND PasswordVerificationTokenExpirationDate > @1)", userId, DateTime.UtcNow);
                if (token == null) {
                    token = GenerateToken();

                    int rows = db.Execute(@"UPDATE " + MembershipTableName + " SET PasswordVerificationToken = @0, PasswordVerificationTokenExpirationDate = @1 WHERE (UserId = @2)", token, DateTime.UtcNow.AddMinutes(tokenExpirationInMinutesFromNow), userId);
                    if (rows != 1) {
                        throw new ProviderException(WebDataResources.Security_DbFailure);
                    }
                }
                else {
                    // TODO: should we update expiry again?
                }
                return token;
            }
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override bool IsConfirmed(string userName) {
            VerifyInitialized();
            if (userName.IsEmpty()) throw ExceptionHelper.CreateArgumentNullOrEmptyException("username");

            using (var db = ConnectToDatabase()) {
                int userId = VerifyUserNameHasConfirmedAccount(db, userName, throwException: false);
                return (userId != -1);
            }
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override bool ResetPasswordWithToken(string token, string newPassword) {
            VerifyInitialized();
            if (newPassword.IsEmpty()) {
                throw ExceptionHelper.CreateArgumentNullOrEmptyException("newPassword");
            }
            using (var db = ConnectToDatabase()) {
                int? userId = db.QueryValue(@"SELECT UserId FROM " + MembershipTableName + " WHERE (PasswordVerificationToken = @0 AND PasswordVerificationTokenExpirationDate > @1)", token, DateTime.UtcNow);
                if (userId != null) {
                    bool success = SetPassword(db, userId.Value, newPassword);
                    if (success) {
                        // Clear the Token on success
                        int rows = db.Execute(@"UPDATE " + MembershipTableName + " SET PasswordVerificationToken = NULL, PasswordVerificationTokenExpirationDate = NULL WHERE (UserId = @0)", userId);
                        if (rows != 1) {
                            throw new ProviderException(WebDataResources.Security_DbFailure);
                        }
                    }
                    return success;
                }
                else {
                    return false;
                }
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override void UpdateUser(MembershipUser user) {
            if (!InitializeCalled) {
                PreviousProvider.UpdateUser(user);
            }
            else {
                throw new NotSupportedException();
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool UnlockUser(string userName) {
            if (!InitializeCalled) {
                return PreviousProvider.UnlockUser(userName);
            }
            throw new NotSupportedException();
        }

        internal void ValidateUserTable() {
            using (var db = ConnectToDatabase()) {
                // GetUser will fail with an exception if the user table isn't set up properly
                try {
                    GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, "z");
                }
                catch (Exception e) {
                    throw new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, WebDataResources.Security_FailedToFindUserTable, UserTableName), e);
                }
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool ValidateUser(string username, string password) {
            if (!InitializeCalled) {
                return PreviousProvider.ValidateUser(username, password);
            }
            if (username.IsEmpty()) throw ExceptionHelper.CreateArgumentNullOrEmptyException("username");
            if (password.IsEmpty()) throw ExceptionHelper.CreateArgumentNullOrEmptyException("password");

            using (var db = ConnectToDatabase()) {
                int userId = VerifyUserNameHasConfirmedAccount(db, username, throwException: false);
                if (userId == -1) return false;
                else return CheckPassword(db, userId, password);
            }
        }
    }
}
