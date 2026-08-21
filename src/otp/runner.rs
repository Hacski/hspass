use anyhow::Result;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::io::{stdout, Write};
use std::thread::sleep;
use std::time::Duration;

pub struct ContinuousOtpRunner;

impl ContinuousOtpRunner {
    /// Run live continuous 30s TOTP countdown terminal ticker until user presses Ctrl+C or q
    pub fn run_continuous_totp(service: &str, secret_bytes: &[u8], watch_once: bool) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout_handle = stdout();
        execute!(stdout_handle, Hide)?;

        let mut last_code = String::new();

        loop {
            let (code, remaining) = crate::otp::OtpEngine::current_totp(secret_bytes)?;
            let progress = crate::otp::OtpEngine::format_progress_bar(remaining);

            if code != last_code {
                last_code = code.clone();
            }

            print!(
                "\rLive TOTP for [{}]: {}  Time: {} (Press q to exit)",
                service, code, progress
            );
            stdout_handle.flush()?;

            if watch_once && remaining == 30 {
                println!("\nTOTP expired and refreshed. Exiting single window watcher.");
                break;
            }

            if event::poll(Duration::from_millis(200))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('c') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => break,
                        _ => {}
                    }
                }
            }

            sleep(Duration::from_millis(100));
        }

        execute!(stdout_handle, Show)?;
        disable_raw_mode()?;
        println!();
        Ok(())
    }
}
