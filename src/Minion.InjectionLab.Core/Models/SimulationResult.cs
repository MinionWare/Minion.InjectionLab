using System.Collections.Generic;

namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// The outcome shown under "What the engine sees" / "What happens". This is always
/// produced by scenario-specific, rule-based narration — the app never opens a real
/// connection or executes anything against a database.
/// </summary>
public sealed class SimulationResult
{
    public required Severity Severity { get; init; }
    public required string Headline { get; init; }      // e.g. "Authentication bypassed"
    public required string Detail { get; init; }         // longer explanation of what the engine would do

    /// <summary>
    /// Short "blast radius" lines for compound/escalation scenarios, e.g.
    /// ["dbo.Users — 4,812 rows exposed", "Login 'webapp' added to sysadmin"].
    /// Null/empty for simple scenarios — the view hides this section entirely.
    /// </summary>
    public IReadOnlyList<string>? AffectedAssets { get; init; }

    /// <summary>
    /// A simulated exfiltrated data preview for UNION/data-dump style scenarios — rendered as a
    /// small grid that reveals row by row. Column order follows each row's own key order.
    /// Entirely fabricated/representative data, never real — this never queries anything.
    /// </summary>
    public IReadOnlyList<IReadOnlyDictionary<string, string>>? LeakedRows { get; init; }

    /// <summary>Button label for revealing LeakedRows, e.g. "1 row" or "47 rows — the entire Users table".</summary>
    public string? RowCountLabel { get; init; }
}
