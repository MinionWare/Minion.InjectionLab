namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// High-level grouping shown as section headers in the attack list.
/// </summary>
public enum AttackCategory
{
    ClassicInBand,
    BlindInferential,
    OutOfBand,
    DeliveryObfuscation,
    IdentifiersAndDynamicSql,
    PostInjectionImpact,
    SqlServerAgentAndJobs,
    NonSqlInjection
}
