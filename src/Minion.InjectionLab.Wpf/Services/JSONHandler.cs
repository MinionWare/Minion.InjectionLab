using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IO;

namespace Minion.Shared.Config
{
    /// <summary>
    /// Handles reading and writing JSON configuration files (UserConfig.json).
    /// </summary>
    public class JSONHandler : IJSONHandler
    {
        private readonly string _filePath;

        public JSONHandler(string filePath)
        {
            _filePath = filePath;
            if (!File.Exists(_filePath))
                File.WriteAllText(_filePath, "{}");
        }

        private JObject ReadJson()
        {
            var jsonContent = File.ReadAllText(_filePath);
            return JObject.Parse(jsonContent);
        }

        public void WriteOrUpdateSection(string section, object data)
        {
            JObject json;
            try { json = ReadJson(); }
            catch (JsonReaderException) { json = new JObject(); }

            json[section] = JToken.FromObject(data);
            File.WriteAllText(_filePath, json.ToString(Formatting.Indented));
        }

        public void DeleteSection(string section)
        {
            JObject json;
            try { json = ReadJson(); }
            catch (JsonReaderException) { json = new JObject(); }

            if (json.ContainsKey(section))
            {
                json.Remove(section);
                File.WriteAllText(_filePath, json.ToString(Formatting.Indented));
            }
        }

        public T GetSection<T>(string section) where T : class
        {
            JObject json;
            try { json = ReadJson(); }
            catch (JsonReaderException) { json = new JObject(); }

            if (!json.TryGetValue(section, out JToken? sectionToken) || sectionToken.Type == JTokenType.Null)
                throw new Exception($"Section '{section}' does not exist or is null in the JSON file.");

            var result = sectionToken.ToObject<T>();
            return result ?? throw new Exception($"Section '{section}' could not be deserialized.");
        }
    }
}
