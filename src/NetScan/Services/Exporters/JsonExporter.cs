using System.Text;
using System.Text.Json;
using NetScan.Abstractions;
using NetScan.Models;

namespace NetScan.Services.Exporters;

/// <summary>
/// Exports connection snapshots to JSON format.
/// </summary>
internal sealed class JsonExporter : IConnectionExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public string FileExtension => ".json";

    public async Task ExportAsync(ConnectionSnapshot snapshot, string filePath, CancellationToken cancellationToken = default)
    {
        string fullPath = filePath.EndsWith(FileExtension, StringComparison.OrdinalIgnoreCase)
            ? filePath
            : filePath + FileExtension;

        // Ensure directory exists
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(snapshot, JsonOptions);
        await File.WriteAllTextAsync(fullPath, json, Encoding.UTF8, cancellationToken);
    }
}
