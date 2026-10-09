using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Behaviors;

/// <summary>
/// Attached property: whenever the bound "Trigger" value changes, plays a severity-appropriate
/// burst of motion on the element — a shake + red glow for a breach, a calm green glow + pop for
/// a blocked attempt. Reads "Severity" at the moment the trigger fires to decide which.
/// </summary>
public static class ImpactBehavior
{
    public static readonly DependencyProperty TriggerProperty =
        DependencyProperty.RegisterAttached("Trigger", typeof(object), typeof(ImpactBehavior),
            new PropertyMetadata(null, OnTriggerChanged));

    public static void SetTrigger(DependencyObject element, object value) => element.SetValue(TriggerProperty, value);
    public static object GetTrigger(DependencyObject element) => element.GetValue(TriggerProperty);

    public static readonly DependencyProperty SeverityProperty =
        DependencyProperty.RegisterAttached("Severity", typeof(Severity?), typeof(ImpactBehavior),
            new PropertyMetadata(null));

    public static void SetSeverity(DependencyObject element, Severity? value) => element.SetValue(SeverityProperty, value);
    public static Severity? GetSeverity(DependencyObject element) => (Severity?)element.GetValue(SeverityProperty);

    private static void OnTriggerChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement element || e.OldValue is null) return;

        if (element.RenderTransform is not TransformGroup)
        {
            element.RenderTransform = new TransformGroup
            {
                Children = { new ScaleTransform(1, 1), new TranslateTransform(0, 0) }
            };
        }
        element.RenderTransformOrigin = new Point(0.5, 0.5);
        var group = (TransformGroup)element.RenderTransform;
        var scale = (ScaleTransform)group.Children[0];
        var translate = (TranslateTransform)group.Children[1];

        var severity = GetSeverity(d);
        var glowColor = severity switch
        {
            Severity.Critical => Color.FromRgb(0xFF, 0x5C, 0x6C),
            Severity.Warning => Color.FromRgb(0xFF, 0xB4, 0x54),
            Severity.Blocked => Color.FromRgb(0x3D, 0xD6, 0x8C),
            Severity.Success => Color.FromRgb(0x5A, 0xA7, 0xFF),
            _ => Color.FromRgb(0x5A, 0xA7, 0xFF)
        };

        element.Effect = new DropShadowEffect
        {
            Color = glowColor,
            BlurRadius = 0,
            ShadowDepth = 0,
            Opacity = 0.9
        };
        var effect = (DropShadowEffect)element.Effect;

        if (severity == Severity.Critical)
        {
            // Shake: a few quick decaying oscillations — reads as "something broke in"
            var shake = new DoubleAnimationUsingKeyFrames();
            double[] offsets = { 0, -8, 7, -6, 5, -3, 2, 0 };
            for (int i = 0; i < offsets.Length; i++)
                shake.KeyFrames.Add(new LinearDoubleKeyFrame(offsets[i], KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(i * 45))));
            translate.BeginAnimation(TranslateTransform.XProperty, shake);

            AnimateGlow(effect, 22, 0.35);
        }
        else if (severity is Severity.Blocked or Severity.Success)
        {
            var pop = new DoubleAnimationUsingKeyFrames
            {
                KeyFrames =
                {
                    new EasingDoubleKeyFrame(0.96, KeyTime.FromTimeSpan(TimeSpan.Zero)),
                    new EasingDoubleKeyFrame(1.03, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(120)),
                        new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.5 }),
                    new EasingDoubleKeyFrame(1.0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(260)))
                }
            };
            scale.BeginAnimation(ScaleTransform.ScaleXProperty, pop);
            scale.BeginAnimation(ScaleTransform.ScaleYProperty, pop);

            AnimateGlow(effect, 16, 0.6);
        }
        else
        {
            AnimateGlow(effect, 10, 0.4);
        }
    }

    private static void AnimateGlow(DropShadowEffect effect, double peakBlur, double duration)
    {
        var blur = new DoubleAnimationUsingKeyFrames
        {
            KeyFrames =
            {
                new EasingDoubleKeyFrame(peakBlur, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(duration * 0.25))),
                new EasingDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(duration)))
            }
        };
        effect.BeginAnimation(DropShadowEffect.BlurRadiusProperty, blur);
    }
}
