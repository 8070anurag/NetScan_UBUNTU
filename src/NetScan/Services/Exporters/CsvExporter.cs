using System.Globalization;
using System.Text;
using NetScan.Abstractions;
using NetScan.Models;

namespace NetScan.Services.Exporters;

/// <summary>
/// Exports connection snapshots to CSV format.
/// </summary>
internal sealed class CsvExporter : IConnectionExporter
{
    public string FileExtension => ".csv";

    public async Task ExportAsync(ConnectionSnapshot snapshot, string filePath, CancellationToken cancellationToken = default)
    {
        string fullPath = filePath.EndsWith(FileExtension, StringComparison.OrdinalIgnoreCase)
            ? filePath
            : filePath + FileExtension;

        // Ensure directory exists
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        var sb = new StringBuilder();

        // Header
        sb.AppendLine("Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,PID,ProcessName,UserName,CommandLine,CapturedAtUtc");

        // Data rows
        foreach (var conn in snapshot.Connections)
        {
            cancellationToken.ThrowIfCancellationRequested();

            sb.Append(Escape(conn.Protocol)).Append(',');
            sb.Append(Escape(conn.LocalAddress)).Append(',');
            sb.Append(conn.LocalPort).Append(',');
            sb.Append(Escape(conn.RemoteAddress)).Append(',');
            sb.Append(conn.RemotePort).Append(',');
            sb.Append(Escape(conn.State)).Append(',');
            sb.Append(conn.ProcessId).Append(',');
            sb.Append(Escape(conn.ProcessName)).Append(',');
            sb.Append(Escape(conn.UserName)).Append(',');
            sb.Append(Escape(conn.CommandLine)).Append(',');
            sb.AppendLine(conn.CapturedAtUtc.ToString("o", CultureInfo.InvariantCulture));
        }

        await File.WriteAllTextAsync(fullPath, sb.ToString(), Encoding.UTF8, cancellationToken);
    }

    /// <summary>
    /// Escapes a CSV field value, quoting if it contains special characters.
    /// </summary>
    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
        {
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }

        return value;
    }
}
