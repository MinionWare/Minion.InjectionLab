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
        // Next up: comment truncation/error-based (classic/in-band), out-of-band (xp_dirtree/
        // OPENROWSET), hex/char encoding + Unicode smuggling (delivery/obfuscation), the stored
        // payload -> rendered-page scenario, post-injection impact (xp_cmdshell/linked-server/
        // privilege escalation), SQL Agent job step -> admin, non-SQL injection (v1.1).
    };
}
