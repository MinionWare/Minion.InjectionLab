using CommunityToolkit.Mvvm.ComponentModel;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.ViewModels;

public partial class FieldValueViewModel : ObservableObject
{
    public FormField Field { get; }

    /// <summary>The scenario's baseline ("normal user") value for this field, if any — shown as a
    /// persistent hint under the box so it's always visible, not just when you happen to clear it.</summary>
    public string? BaselineValue { get; }

    public bool HasBaselineValue => !string.IsNullOrEmpty(BaselineValue);

    [ObservableProperty]
    private string value;

    public FieldValueViewModel(FormField field, string? baselineValue = null)
    {
        Field = field;
        value = field.DefaultValue;
        BaselineValue = baselineValue;
    }
}
