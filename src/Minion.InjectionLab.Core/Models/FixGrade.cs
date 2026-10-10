namespace Minion.InjectionLab.Core.Models;

/// <summary>How complete a given fix is — several real fixes can coexist for the same attack,
/// and not all of them close every gap.</summary>
public enum FixGrade
{
    Partial,    // addresses part of the problem, a real gap remains
    Good,       // solid, standard practice, minor edge cases may remain
    Best        // closes the hole as far as this scenario is concerned
}
