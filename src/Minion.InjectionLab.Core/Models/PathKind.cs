namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// The three broad shapes any input to a vulnerable query falls into. Used to color/highlight
/// the "decision path" diagram live, as the user types — before they ever hit Submit.
/// </summary>
public enum PathKind
{
    Safe,       // ordinary, well-formed input that does what it looks like it does
    Neutral,    // ordinary input that simply doesn't match anything (e.g. a typo'd password)
    Malicious   // input shaped like an attack payload
}
