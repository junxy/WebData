using System;
using System.ComponentModel;

namespace System.Web.WebPages {
    public static class StringExtensions {

        public static bool IsEmpty(this string value) {
            return String.IsNullOrEmpty(value);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", MessageId = "int", Justification = "We specificaly want type names")]
        public static int AsInt(this string value) {
            return As<int>(value);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", MessageId = "int", Justification = "We specificaly want type names")]
        public static int AsInt(this string value, int defaultValue) {
            return As<int>(value, defaultValue);
        }

        public static decimal AsDecimal(this string value) {
            return As<decimal>(value);
        }

        public static decimal AsDecimal(this string value, decimal defaultValue) {
            return As<decimal>(value, defaultValue);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", MessageId = "float", Justification="We specificaly want type names")]
        public static float AsFloat(this string value) {
            return As<float>(value);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", MessageId = "float", Justification = "We specificaly want type names")]
        public static float AsFloat(this string value, float defaultValue) {
            return As<float>(value, defaultValue);
        }

        public static DateTime AsDateTime(this string value) {
            return As<DateTime>(value);
        }

        public static DateTime AsDateTime(this string value, DateTime defaultValue) {
            return As<DateTime>(value, defaultValue);
        }

        public static TValue As<TValue>(this string value) {
            return As<TValue>(value, default(TValue));
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", MessageId = "bool", Justification = "We specificaly want type names")]
        public static bool AsBool(this string value) {
            return As<bool>(value, false);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", MessageId = "bool", Justification = "We specificaly want type names")]
        public static bool AsBool(this string value, bool defaultValue) {
            return As<bool>(value, defaultValue);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes", Justification="We want to make this user friendly and return the default value on all failures")]
        public static TValue As<TValue>(this string value, TValue defaultValue) {
            try {
                TypeConverter converter = TypeDescriptor.GetConverter(typeof(TValue));
                if (converter.CanConvertFrom(typeof(string))) {
                    return (TValue)converter.ConvertFrom(value);
                }
                // try the other direction
                converter = TypeDescriptor.GetConverter(typeof(string));
                if (converter.CanConvertTo(typeof(TValue))) {
                    return (TValue)converter.ConvertTo(value, typeof(TValue));
                }
            }
            catch (Exception) {
                // eat all exceptions and return the defaultValue, assumption is that its always a parse/format exception
            }
            return defaultValue;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", MessageId = "bool", Justification = "We specificaly want type names")]
        public static bool IsBool(this string value) {
            return Is<bool>(value);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", MessageId = "int", Justification = "We specificaly want type names")]
        public static bool IsInt(this string value) {
            return Is<int>(value);
        }

        public static bool IsDecimal(this string value) {
            return Is<decimal>(value);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", MessageId = "float", Justification = "We specificaly want type names")]
        public static bool IsFloat(this string value) {
            return Is<float>(value);
        }

        public static bool IsDateTime(this string value) {
            return Is<DateTime>(value);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1004:GenericMethodsShouldProvideTypeParameter", Justification="This is the signature we want")]
        public static bool Is<TValue>(this string value) {
            TypeConverter converter = TypeDescriptor.GetConverter(typeof(TValue));
            if (converter != null) {
                if (converter.CanConvertFrom(typeof(string))) {
                    return converter.IsValid(value);
                }
            }
            return false;
        }

    }
}
