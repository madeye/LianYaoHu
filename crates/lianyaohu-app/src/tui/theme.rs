//! Shared visual language for the quick-pick and the config editor: one
//! accent palette, one keybar style, one status-line style. Keeping these in
//! a single module is what makes the two surfaces feel like the same tool.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Accent for focus indicators (selected pane border, keybar keys).
pub const ACCENT: Color = Color::Cyan;
/// Scope badge colors: global vs project must be distinguishable at a glance.
pub const SCOPE_GLOBAL: Color = Color::Cyan;
pub const SCOPE_PROJECT: Color = Color::Magenta;

pub fn key_style() -> Style {
    Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn dim_style() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}

pub fn success_style() -> Style {
    Style::new().fg(Color::Green)
}

pub fn warn_style() -> Style {
    Style::new().fg(Color::Yellow)
}

pub fn error_style() -> Style {
    Style::new().fg(Color::Red)
}

pub fn up_style() -> Style {
    Style::new().fg(Color::Green)
}

pub fn down_style() -> Style {
    Style::new().fg(Color::Red).add_modifier(Modifier::DIM)
}

/// Renders `(key, action)` pairs as one keybar line: keys pop in the accent
/// color, actions stay dim, separated by a middle dot.
pub fn keybar_line(items: &[(&str, &str)]) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(items.len() * 3);
    for (index, (key, action)) in items.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", dim_style()));
        }
        spans.push(Span::styled((*key).to_string(), key_style()));
        spans.push(Span::styled(format!(" {action}"), dim_style()));
    }
    Line::from(spans)
}

/// `[up]` / `[down]` interface state as a colored span.
pub fn state_span(up: bool) -> Span<'static> {
    if up {
        Span::styled("[up]", up_style())
    } else {
        Span::styled("[down]", down_style())
    }
}
