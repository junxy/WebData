﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Internal.Web.Utils;
using WebMatrix.Data.Resources;

namespace WebMatrix.Data {
    public class Database : IDisposable {
        internal const string SqlCeProviderName = "System.Data.SqlServerCe.4.0";
        internal const string SqlServerProviderName = "System.Data.SqlClient";

        internal static string DataDirectory = (string)AppDomain.CurrentDomain.GetData("DataDirectory") ?? Directory.GetCurrentDirectory();
        private static event EventHandler<ConnectionEventArgs> _connectionOpened;

        private Func<DbConnection> _connectionFactory;
        private DbConnection _connection;

        private const string DefaultDataProviderAppSetting = "systemData:defaultProvider";
        private static readonly IDictionary<string, IDbFileHandler> _dbFileHandlers = new Dictionary<string, IDbFileHandler>(StringComparer.OrdinalIgnoreCase) {
            { ".sdf", new SqlCeDbFileHandler() },
            { ".mdf", new SqlServerDbFileHandler() }
        };

        private static readonly IConfigurationManager _configurationManager = new ConfigurationManagerWrapper(_dbFileHandlers);

        internal Database(Func<DbConnection> connectionFactory) {
            _connectionFactory = connectionFactory;
        }

        public DbConnection Connection {
            get {
                if (_connection == null) {
                    _connection = _connectionFactory();
                }
                return _connection;
            }
        }

        public static event EventHandler<ConnectionEventArgs> ConnectionOpened {
            add {
                _connectionOpened += value;
            }
            remove {
                _connectionOpened -= value;
            }
        }

        public void Close() {
            Dispose();
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing) {
            if (disposing) {
                if (_connection != null) {
                    _connection.Close();
                    _connection = null;
                }
            }
        }

        public DataRow QuerySingle(string commandText, params object[] args) {
            if (String.IsNullOrEmpty(commandText)) {
                throw ExceptionHelper.CreateArgumentNullOrEmptyException("commandText");
            }
            var dt = QueryInternal(commandText, args);
            return dt != null && dt.Rows.Count > 0 ? dt.Rows[0] : null;
        }

        public DataTable Query(string commandText, params object[] parameters) {
            if (String.IsNullOrEmpty(commandText)) {
                throw ExceptionHelper.CreateArgumentNullOrEmptyException("commandText");
            }
            // Return a readonly collection
            return QueryInternal(commandText, parameters);
        }

        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Users are responsible for ensuring the inputs to this method are SQL Injection sanitized")]
        private DataTable QueryInternal(string commandText, params object[] parameters) {
            EnsureConnectionOpen();

            DbCommand command = Connection.CreateCommand();
            command.CommandText = commandText;

            AddParameters(command, parameters);
            using (command) {
                //IEnumerable<string> columnNames = null;
                using (DbDataReader reader = command.ExecuteReader()) {
                    //foreach (DbDataRecord record in reader) {
                    //    if (columnNames == null) {
                    //        columnNames = GetColumnNames(record);
                    //    }
                    //    yield return new DynamicRecord(columnNames, record);
                    //}
                    var dt = new DataTable();
                    dt.Load(reader);
                    return dt;
                }
            }
        }

        private static IEnumerable<string> GetColumnNames(DbDataRecord record) {
            // Get all of the column names for this query
            for (int i = 0; i < record.FieldCount; i++) {
                yield return record.GetName(i);
            }
        }

        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Users are responsible for ensuring the inputs to this method are SQL Injection sanitized")]
        public int Execute(string commandText, params object[] args) {
            if (String.IsNullOrEmpty(commandText)) {
                throw ExceptionHelper.CreateArgumentNullOrEmptyException("commandText");
            }

            EnsureConnectionOpen();

            DbCommand command = Connection.CreateCommand();
            command.CommandText = commandText;

            AddParameters(command, args);
            using (command) {
                return command.ExecuteNonQuery();
            }
        }

        [SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate", Justification = "This makes a database request")]
        public object GetLastInsertId() {
            // This method only support sql ce and sql server for now
            return QueryValue("SELECT @@Identity");
        }

        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Users are responsible for ensuring the inputs to this method are SQL Injection sanitized")]
        public object QueryValue(string commandText, params object[] args) {
            if (String.IsNullOrEmpty(commandText)) {
                throw ExceptionHelper.CreateArgumentNullOrEmptyException("commandText");
            }

            EnsureConnectionOpen();

            DbCommand command = Connection.CreateCommand();
            command.CommandText = commandText;

            AddParameters(command, args);
            using (command) {
                return command.ExecuteScalar();
            }
        }

        private void EnsureConnectionOpen() {
            // If the connection isn't open then open it
            if (Connection.State != ConnectionState.Open) {
                Connection.Open();

                // Raise the connection opened event
                OnConnectionOpened();
            }
        }

        private void OnConnectionOpened() {
            if (_connectionOpened != null) {
                _connectionOpened(this, new ConnectionEventArgs(Connection));
            }
        }

        private static void AddParameters(DbCommand command, object[] args) {
            if (args == null) {
                return;
            }

            // Create numbered parameters
            IEnumerable<DbParameter> parameters = args.Select((o, index) => {
                var parameter = command.CreateParameter();
                parameter.ParameterName = index.ToString(CultureInfo.InvariantCulture);
                parameter.Value = o;
                return parameter;
            });

            foreach (var p in parameters) {
                command.Parameters.Add(p);
            }
        }

        public static Database OpenConnectionString(string connectionString) {
            return OpenConnectionString(connectionString, providerName: null);
        }

        public static Database OpenConnectionString(string connectionString, string providerName) {
            if (String.IsNullOrEmpty(connectionString)) {
                throw ExceptionHelper.CreateArgumentNullOrEmptyException("connectionString");
            }

            return OpenConnectionStringInternal(providerName, connectionString);
        }

        public static Database Open(string name) {
            if (String.IsNullOrEmpty(name)) {
                throw ExceptionHelper.CreateArgumentNullOrEmptyException("name");
            }
            return OpenNamedConnection(name, _configurationManager);
        }

        internal static IConnectionConfiguration GetConnectionConfiguration(string fileName, IDictionary<string, IDbFileHandler> handlers) {
            string extension = Path.GetExtension(fileName);
            IDbFileHandler handler;
            if (handlers.TryGetValue(extension, out handler)) {
                return handler.GetConnectionConfiguration(fileName);
            }

            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                DataResources.UnableToDetermineDatabase, fileName));
        }

        private static Database OpenConnectionStringInternal(string providerName, string connectionString) {
            return OpenConnectionStringInternal(new DbProviderFactoryWrapper(providerName), connectionString);
        }

        private static Database OpenConnectionInternal(IConnectionConfiguration connectionConfig) {
            return OpenConnectionStringInternal(connectionConfig.ProviderFactory, connectionConfig.ConnectionString);
        }

        internal static Database OpenConnectionStringInternal(IDbProviderFactory providerFactory, string connectionString) {
            return new Database(() => providerFactory.CreateConnection(connectionString));
        }

        internal static Database OpenNamedConnection(string name, IConfigurationManager configurationManager) {
            // Opens a connection using the connection string setting with the specified name
            IConnectionConfiguration configuration = configurationManager.GetConnection(name);
            if (configuration != null) {
                // We've found one in the connection string setting in config so use it
                return OpenConnectionInternal(configuration);
            }

            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                DataResources.ConnectionStringNotFound, name));
        }

        internal static string GetDefaultProviderName() {
            string providerName;
            // Get the default provider name from config if there is any
            if (!_configurationManager.AppSettings.TryGetValue(DefaultDataProviderAppSetting, out providerName)) {
                providerName = SqlCeProviderName;
            }

            return providerName;
        }
    }
}