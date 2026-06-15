using NetScan.Models;

namespace NetScan.Abstractions;

/// <summary>
/// Interface for exporting connection data to various formats.
/// </summary>
public interface IConnectionExporter
{
    /// <summary>The file extension this exporter produces (e.g., ".json", ".csv").</summary>
    string FileExtension { get; }

    /// <summary>
    /// Exports a connection snapshot to the specified file path.
    /// </summary>
    /// <param name="snapshot">The snapshot to export.</param>
    /// <param name="filePath">Target file path (without extension).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task ExportAsync(ConnectionSnapshot snapshot, string filePath, CancellationToken cancellationToken = default);
}
