﻿namespace WebMatrix.Data {
    using System;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;

    internal class SqlCeDbFileHandler : IDbFileHandler {
        private const string SqlCeConnectionStringFormat = @"Data Source={0}";

        public IConnectionConfiguration GetConnectionConfiguration(string fileName) {
            // Get the default provider name
            string providerName = Database.GetDefaultProviderName();
            Debug.Assert(!String.IsNullOrEmpty(providerName), "Provider name should not be null or empty");

            string connectionString = GetConnectionString(fileName);
            return new ConnectionConfiguration(providerName, connectionString);
        }

        public static string GetConnectionString(string fileName) {
            if (Path.IsPathRooted(fileName)) {
                return String.Format(CultureInfo.InvariantCulture, SqlCeConnectionStringFormat, fileName);
            }

            // Use |DataDirectory| if the path isn't rooted
            string dataSource = @"|DataDirectory|\" + Path.GetFileName(fileName);
            return String.Format(CultureInfo.InvariantCulture, SqlCeConnectionStringFormat, dataSource);
        }
    }
}