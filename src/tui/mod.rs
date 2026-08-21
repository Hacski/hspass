use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use std::io;
use crate::vault::VaultData;

pub fn run_tui(vault: &VaultData) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut list_state = ListState::default();
    let services: Vec<String> = vault.credentials.keys().cloned().collect();
    if !services.is_empty() {
        list_state.select(Some(0));
    }

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
                .split(f.area());

            let items: Vec<ListItem> = services
                .iter()
                .map(|s| ListItem::new(s.as_str()))
                .collect();

            let list = List::new(items)
                .block(Block::default().title(" Vault Services ").borders(Borders::ALL))
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                );

            f.render_stateful_widget(list, chunks[0], &mut list_state);

            let selected_details = match list_state.selected() {
                Some(idx) => {
                    let service = &services[idx];
                    if let Some(cred) = vault.credentials.get(service) {
                        format!(
                            "Service: {}\nUsername: {}\nPassword: [HIDDEN - Press 'p' to reveal]\nURL: {}\nCreated: {}",
                            cred.service,
                            cred.username,
                            cred.url.as_deref().unwrap_or("N/A"),
                            cred.created_at
                        )
                    } else {
                        "No details available".to_string()
                    }
                }
                None => "Select a service from the left menu".to_string(),
            };

            let details = Paragraph::new(selected_details)
                .block(Block::default().title(" Credential Details ").borders(Borders::ALL));
            f.render_widget(details, chunks[1]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        if !services.is_empty() {
                            let next = match list_state.selected() {
                                Some(i) => (i + 1) % services.len(),
                                None => 0,
                            };
                            list_state.select(Some(next));
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if !services.is_empty() {
                            let prev = match list_state.selected() {
                                Some(i) => {
                                    if i == 0 {
                                        services.len() - 1
                                    } else {
                                        i - 1
                                    }
                                }
                                None => 0,
                            };
                            list_state.select(Some(prev));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
