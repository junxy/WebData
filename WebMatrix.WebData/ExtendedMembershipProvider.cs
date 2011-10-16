using System;
using System.Collections.Generic;
using System.Web.Security;

namespace WebMatrix.WebData {
    public abstract class ExtendedMembershipProvider : MembershipProvider {
        private const int OneDayInMinutes = 24 * 60;

        public virtual string CreateUserAndAccount(string userName, string password) {
            return CreateUserAndAccount(userName, password, requireConfirmation: false, values: null);
        }

        public virtual string CreateUserAndAccount(string userName, string password, bool requireConfirmation) {
            return CreateUserAndAccount(userName, password, requireConfirmation, values: null);
        }

        public virtual string CreateUserAndAccount(string userName, string password, IDictionary<string, object> values) {
            return CreateUserAndAccount(userName, password, requireConfirmation: false, values: values);
        }

        public abstract string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values);
        
        public virtual string CreateAccount(string userName, string password) {
            return CreateAccount(userName, password, requireConfirmationToken: false);
        }
        
        public abstract string CreateAccount(string userName, string password, bool requireConfirmationToken);
        public abstract bool ConfirmAccount(string accountConfirmationToken);
        public abstract bool DeleteAccount(string userName);
        
        public virtual string GeneratePasswordResetToken(string userName) {
            return GeneratePasswordResetToken(userName, tokenExpirationInMinutesFromNow: OneDayInMinutes);
        }

        public abstract string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow);
        public abstract int GetUserIdFromPasswordResetToken(string token);
        public abstract bool IsConfirmed(string userName);
        public abstract bool ResetPasswordWithToken(string token, string newPassword);
        public abstract int GetPasswordFailuresSinceLastSuccess(string userName);
        public abstract DateTime GetCreateDate(string userName);
        public abstract DateTime GetPasswordChangedDate(string userName);
        public abstract DateTime GetLastPasswordFailureDate(string userName);

        internal virtual void VerifyInitialized() {}
    }
}
