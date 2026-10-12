namespace Minion.Shared.Config
{
    /// <summary>
    /// Defines methods for interacting with JSON configuration files.
    /// Provides functionalities to write or update JSON sections, delete sections,
    /// and retrieve specific sections from the configuration.
    /// </summary>
    public interface IJSONHandler
    {
        /// <summary>Writes a new section or updates an existing section in the JSON file.</summary>
        void WriteOrUpdateSection(string section, object data);

        /// <summary>Deletes a specified section from the JSON configuration file.</summary>
        void DeleteSection(string section);

        /// <summary>Retrieves a specific section from the JSON file as a strongly-typed object.</summary>
        T GetSection<T>(string section) where T : class;
    }
}
