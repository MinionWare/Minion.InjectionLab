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
        // Next up: UnionSelectScenario, StackedQueriesScenario, BlindBooleanScenario,
        // TimeBasedBlindScenario, DynamicSqlStoredProcScenario, IdentifierInjectionScenario,
        // SecondOrderScenario, StoredPayloadXssScenario, SqlAgentJobStepScenario, ...
    };
}
