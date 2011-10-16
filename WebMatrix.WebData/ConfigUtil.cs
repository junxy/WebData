using System;
using System.Configuration;

namespace WebMatrix.WebData {
    internal static class ConfigUtil {
        private static bool _simpleMembershipEnabled = IsSimpleMembershipEnabled();
        private static string _loginUrl = GetLoginUrl();

        public static bool SimpleMembershipEnabled {
            get { return _simpleMembershipEnabled; }
        }

        public static string LoginUrl {
            get { return _loginUrl; }
        }

        private static string GetLoginUrl() {
            return ConfigurationManager.AppSettings[FormsAuthenticationSettings.LoginUrlKey] ?? 
                   FormsAuthenticationSettings.DefaultLoginUrl;
        }

        private static bool IsSimpleMembershipEnabled() {
            string settingValue = ConfigurationManager.AppSettings[WebSecurity.EnableSimpleMembershipKey];
            bool enabled;
            if (!String.IsNullOrEmpty(settingValue) && Boolean.TryParse(settingValue, out enabled)) {
                return enabled;
            }
            // Simple Membership is enabled by default, but attempts to delegate to the current provider if not initialized.
            return true;
        }
    }
}
