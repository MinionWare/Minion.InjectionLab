using Microsoft.SqlServer.TransactSql.ScriptDom;

namespace Minion.InjectionLab.Core.Services;

/// <summary>
/// Real T-SQL syntax validation via Microsoft's own parser (ScriptDom — the same engine behind
/// SSDT/SqlPackage), instead of hand-rolled heuristics like "does this end with --". Scenarios
/// use this to classify a payload as a genuine SQL Server parse error rather than guessing from
/// string patterns, which is both more accurate and automatically correct for payload shapes
/// nobody thought to special-case.
/// </summary>
public static class SqlSyntaxChecker
{
    /// <summary>True if SQL Server would reject this batch outright with a parse error.</summary>
    public static bool HasSyntaxError(string sql)
    {
        var parser = new TSql160Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(sql);
        parser.Parse(reader, out IList<ParseError> errors);
        return errors is { Count: > 0 };
    }

    /// <summary>The parser's own error messages, for when a scenario wants to show exactly what
    /// SQL Server would say (line/column plus message) rather than just a yes/no.</summary>
    public static IReadOnlyList<string> GetSyntaxErrors(string sql)
    {
        var parser = new TSql160Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(sql);
        parser.Parse(reader, out IList<ParseError> errors);
        return errors?.Select(e => $"Line {e.Line}: {e.Message}").ToList() ?? new List<string>();
    }
}
