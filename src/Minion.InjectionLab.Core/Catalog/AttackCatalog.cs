using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Scenarios;

namespace Minion.InjectionLab.Core.Catalog;

/// <summary>
/// The full list of scenarios shown in the left-hand nav. Adding a new attack is:
/// write a new Scenarios/XyzScenario.cs, then add one line here.
/// </summary>
public static class AttackCatalog
{
    public static IReadOnlyList<AttackScenario> All { get; } = new List<AttackScenario>
    {
        TautologyLoginScenario.Create(),
        UnionSelectScenario.Create(),
        StackedQueriesScenario.Create(),
        BooleanBlindScenario.Create(),
        TimeBasedBlindScenario.Create(),
        NumericInjectionScenario.Create(),
        OrderByIdentifierScenario.Create(),
        DynamicSqlStoredProcScenario.Create(),
        SecondOrderScenario.Create(),
        LikeWildcardScenario.Create(),
        OutOfBandExfilScenario.Create(),
        HexEncodedBypassScenario.Create(),
        SqlAgentCmdExecScenario.Create(),
        CommentTruncationScenario.Create(),
        ErrorBasedScenario.Create(),
        InsertUpdateInjectionScenario.Create(),
        ErrorBasedBlindScenario.Create(),
        CommentWhitespaceObfuscationScenario.Create(),
        TruncationAttackScenario.Create(),
        QuotenameLimitScenario.Create(),
        ExecuteAsEscalationScenario.Create(),
        XpCmdshellRceScenario.Create(),
        // Next up: Unicode/homoglyph smuggling, TOP/OFFSET/HAVING injection, the stored-payload
        // -> rendered-page scenario (arguably XSS riding on a SQLi delivery mechanism — needs a
        // design call first), linked-server pivoting, non-SQL injection (v1.1), historical
        // SQL Server OS-level CVEs (v2, history + citations only).
    };
}
