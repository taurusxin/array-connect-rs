use arraysslvpn::{
    CancellationToken, PasswordChallenge, PasswordProvider, Result, SecretString, VpnError,
};
use async_trait::async_trait;
use crossterm::{
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
        KeyModifiers,
    },
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::{
    io::{self, IsTerminal, Write},
    time::Duration,
};

pub struct TerminalPassword;

#[async_trait]
impl PasswordProvider for TerminalPassword {
    async fn password(&self, challenge: PasswordChallenge) -> Result<SecretString> {
        let stop = challenge.cancellation.child_token();
        let _stop_on_drop = stop.clone().drop_guard();
        tokio::task::spawn_blocking(move || read_password(stop, challenge.cancellation))
            .await
            .map_err(|_| VpnError::Io(io::Error::other("password input worker failed")))?
    }
}

struct TerminalGuard {
    paste: bool,
}
impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut guard = Self { paste: false };
        if io::stderr().is_terminal() {
            crossterm::execute!(io::stderr(), EnableBracketedPaste)?;
            guard.paste = true;
        }
        Ok(guard)
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.paste {
            let _ = crossterm::execute!(io::stderr(), DisableBracketedPaste);
        }
        let _ = disable_raw_mode();
        let _ = write!(io::stderr(), "\r\n");
    }
}

enum Input {
    Continue,
    Submit,
    Cancel,
}
fn apply_event(event: Event, password: &mut String) -> io::Result<Input> {
    match event {
        Event::Key(key) if key.kind != KeyEventKind::Release => match key.code {
            KeyCode::Esc => return Ok(Input::Cancel),
            KeyCode::Char('c' | 'd') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(Input::Cancel);
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => password.clear(),
            KeyCode::Enter => return Ok(Input::Submit),
            KeyCode::Backspace => {
                password.pop();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && !c.is_control() =>
            {
                password.push(c)
            }
            _ => {}
        },
        Event::Paste(value) => {
            if value.chars().any(char::is_control) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "password paste must be a single line",
                ));
            }
            password.push_str(&value);
        }
        _ => {}
    }
    if password.len() > 16384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "password exceeds 16384 bytes",
        ));
    }
    Ok(Input::Continue)
}

fn read_password(stop: CancellationToken, parent: CancellationToken) -> Result<SecretString> {
    if stop.is_cancelled() {
        return Err(VpnError::Cancelled);
    }
    let _terminal = TerminalGuard::enter()?;
    write!(io::stderr(), "Password: ")?;
    io::stderr().flush()?;
    // SecretString takes ownership on submission; wipe cancelled/failed input.
    let mut password = secrecy::zeroize::Zeroizing::new(String::new());
    loop {
        if stop.is_cancelled() {
            break Err(VpnError::Cancelled);
        }
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        match apply_event(event::read()?, &mut password)? {
            Input::Continue => {}
            Input::Submit => break Ok(SecretString::from(std::mem::take(&mut *password))),
            Input::Cancel => {
                parent.cancel();
                break Err(VpnError::Cancelled);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;
    #[test]
    fn hidden_input_handles_unicode_backspace_paste_and_cancel() {
        let mut password = String::new();
        apply_event(
            Event::Key(KeyEvent::new(KeyCode::Char('你'), KeyModifiers::NONE)),
            &mut password,
        )
        .unwrap();
        apply_event(
            Event::Key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE)),
            &mut password,
        )
        .unwrap();
        apply_event(Event::Paste("secret密码".into()), &mut password).unwrap();
        assert_eq!(password, "secret密码");
        assert!(matches!(
            apply_event(
                Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
                &mut password
            )
            .unwrap(),
            Input::Submit
        ));
        assert!(matches!(
            apply_event(
                Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
                &mut password
            )
            .unwrap(),
            Input::Cancel
        ));
        assert!(apply_event(Event::Paste("secret\n".into()), &mut password).is_err());
    }
}
