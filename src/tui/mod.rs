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
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Terminal,
};
use std::io;
use crate::vault::VaultData;
use crate::otp::OtpEngine;
use crate::audit::run_vault_audit;

pub enum TuiTab {
    Credentials,
    OtpTokens,
    SecurityAudit,
    Passkeys,
}

pub fn run_tui(vault: &VaultData) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut current_tab = TuiTab::Credentials;
    let mut list_state = ListState::default();
    let mut reveal_password = false;
    let mut filter_query = String::new();
    let mut is_searching = false;

    let services: Vec<String> = vault.credentials.keys().cloned().collect();
    if !services.is_empty() {
        list_state.select(Some(0));
    }

    loop {
        let filtered_services: Vec<String> = services
            .iter()
            .filter(|s| filter_query.is_empty() || s.to_lowercase().contains(&filter_query.to_lowercase()))
            .cloned()
            .collect();

        terminal.draw(|f| {
            let size = f.area();

            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                    Constraint::Length(3),
                ].as_ref())
                .split(size);

            // Tab bar rendering
            let tab_titles = vec![" [1] Credentials ", " [2] Live OTP ", " [3] Security Audit ", " [4] Passkeys "];
            let active_index = match current_tab {
                TuiTab::Credentials => 0,
                TuiTab::OtpTokens => 1,
                TuiTab::SecurityAudit => 2,
                TuiTab::Passkeys => 3,
            };

            let tabs = Tabs::new(tab_titles)
                .block(Block::default().title(" hspass Vault Interactive Dashboard ").borders(Borders::ALL))
                .select(active_index)
                .style(Style::default().fg(Color::Cyan))
                .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
            f.render_widget(tabs, main_chunks[0]);

            // Body rendering based on active tab
            match current_tab {
                TuiTab::Credentials => {
                    let body_chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
                        .split(main_chunks[1]);

                    let items: Vec<ListItem> = filtered_services
                        .iter()
                        .map(|s| ListItem::new(format!("  * {}", s)))
                        .collect();

                    let title = if is_searching {
                        format!(" Services (Filter: {}) ", filter_query)
                    } else {
                        " Services ".to_string()
                    };

                    let list = List::new(items)
                        .block(Block::default().title(title).borders(Borders::ALL))
                        .highlight_style(
                            Style::default()
                                .fg(Color::Black)
                                .bg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        );
                    f.render_stateful_widget(list, body_chunks[0], &mut list_state);

                    let detail_text = match list_state.selected() {
                        Some(idx) if idx < filtered_services.len() => {
                            let service = &filtered_services[idx];
                            if let Some(cred) = vault.credentials.get(service) {
                                let pass_display = if reveal_password {
                                    cred.password.clone()
                                } else {
                                    "******** (Press 'p' to toggle reveal)".to_string()
                                };
                                format!(
                                    "Service Name:  {}\nUsername:      {}\nPassword:      {}\nURL:           {}\nCreated At:    {}\nUpdated At:    {}",
                                    cred.service,
                                    cred.username,
                                    pass_display,
                                    cred.url.as_deref().unwrap_or("N/A"),
                                    cred.created_at,
                                    cred.updated_at
                                )
                            } else {
                                "No details found".to_string()
                            }
                        }
                        _ => "Select a service from the left list".to_string(),
                    };

                    let detail_paragraph = Paragraph::new(detail_text)
                        .block(Block::default().title(" Credential Details ").borders(Borders::ALL))
                        .wrap(Wrap { trim: true });
                    f.render_widget(detail_paragraph, body_chunks[1]);
                }

                TuiTab::OtpTokens => {
                    let otp_services: Vec<(&String, &String)> = vault.totp_entries.iter().collect();
                    if otp_services.is_empty() {
                        let text = Paragraph::new("No TOTP secrets registered in vault.\nRegister secrets using: hspass otp <service> --add-secret <URI>")
                            .block(Block::default().title(" Live OTP Tokens ").borders(Borders::ALL));
                        f.render_widget(text, main_chunks[1]);
                    } else {
                        let chunks = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints(
                                std::iter::repeat(Constraint::Length(4))
                                    .take(otp_services.len())
                                    .collect::<Vec<_>>()
                            )
                            .split(main_chunks[1]);

                        for (i, (svc, sec_str)) in otp_services.iter().enumerate() {
                            if i < chunks.len() {
                                if let Ok(sec_bytes) = OtpEngine::parse_secret(sec_str) {
                                    if let Ok((code, remaining)) = OtpEngine::current_totp(&sec_bytes) {
                                        let ratio = remaining as f64 / 30.0;
                                        let label = format!("{} | Code: {} | {}s remaining", svc, code, remaining);

                                        let gauge = Gauge::default()
                                            .block(Block::default().title(format!(" {} ", svc)).borders(Borders::ALL))
                                            .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
                                            .ratio(ratio)
                                            .label(label);
                                        f.render_widget(gauge, chunks[i]);
                                    }
                                }
                            }
                        }
                    }
                }

                TuiTab::SecurityAudit => {
                    let report = run_vault_audit(vault);
                    let mut text = format!(
                        "Vault Security Health Status:\n  Total Credentials Scan: {}\n  Short Passwords (<12 chars): {}\n  Weak/Common Patterns: {}\n  Reused Passwords: {}\n\nDetected Security Issues:\n",
                        report.total_credentials, report.short_passwords, report.weak_passwords, report.duplicate_passwords
                    );

                    for issue in &report.issues {
                        text.push_str(&format!(
                            "  * [{:?}] {} ({}): {}\n",
                            issue.severity, issue.service, issue.issue_type, issue.description
                        ));
                    }

                    let paragraph = Paragraph::new(text)
                        .block(Block::default().title(" Security Audit Report ").borders(Borders::ALL))
                        .wrap(Wrap { trim: true });
                    f.render_widget(paragraph, main_chunks[1]);
                }

                TuiTab::Passkeys => {
                    let mut text = format!("FIDO2 Passkeys Registered: {}\n\n", vault.passkeys.len());
                    for key in vault.passkeys.keys() {
                        text.push_str(&format!("  * {}\n", key));
                    }

                    let paragraph = Paragraph::new(text)
                        .block(Block::default().title(" FIDO2 Passkeys ").borders(Borders::ALL));
                    f.render_widget(paragraph, main_chunks[1]);
                }
            }

            // Footer instructions bar
            let footer_text = if is_searching {
                " SEARCH MODE: Type query | Press ENTER to confirm | ESC to cancel "
            } else {
                " KEYS: [1-4] Tabs | [j/k] Navigate | [p] Toggle Password | [/] Filter | [q] Exit "
            };
            let footer = Paragraph::new(footer_text)
                .block(Block::default().borders(Borders::ALL))
                .style(Style::default().fg(Color::Yellow));
            f.render_widget(footer, main_chunks[2]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if is_searching {
                    match key.code {
                        KeyCode::Enter | KeyCode::Esc => is_searching = false,
                        KeyCode::Backspace => {
                            filter_query.pop();
                        }
                        KeyCode::Char(c) => {
                            filter_query.push(c);
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('1') => current_tab = TuiTab::Credentials,
                        KeyCode::Char('2') => current_tab = TuiTab::OtpTokens,
                        KeyCode::Char('3') => current_tab = TuiTab::SecurityAudit,
                        KeyCode::Char('4') => current_tab = TuiTab::Passkeys,
                        KeyCode::Char('p') => reveal_password = !reveal_password,
                        KeyCode::Char('/') => {
                            is_searching = true;
                            filter_query.clear();
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if !filtered_services.is_empty() {
                                let next = match list_state.selected() {
                                    Some(i) => (i + 1) % filtered_services.len(),
                                    None => 0,
                                };
                                list_state.select(Some(next));
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if !filtered_services.is_empty() {
                                let prev = match list_state.selected() {
                                    Some(i) => {
                                        if i == 0 {
                                            filtered_services.len() - 1
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
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
