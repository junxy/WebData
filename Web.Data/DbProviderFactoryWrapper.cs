﻿namespace WebMatrix.Data {
    using System;
    using System.Data.Common;
    using Microsoft.Internal.Web.Utils;

    internal class DbProviderFactoryWrapper : IDbProviderFactory {
        private string _providerName;
        private DbProviderFactory _providerFactory;

        public DbProviderFactoryWrapper(string providerName) {            
            _providerName = providerName;
        }

        public DbConnection CreateConnection(string connectionString) {
            if (String.IsNullOrEmpty(_providerName)) {
                // If the provider name is null or empty then use the default
                _providerName = Database.GetDefaultProviderName();
            }

            if (_providerFactory == null) {
                _providerFactory = DbProviderFactories.GetFactory(_providerName);
            }

            DbConnection connection = _providerFactory.CreateConnection();
            connection.ConnectionString = connectionString;
            return connection;
        }
    }
}