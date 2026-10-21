//! A failure before the service's log can be trusted goes to the Event Log (ADR-0013):
//! under the source `PonteAgent`, a fixed event id per kind of failure, and the name of
//! the setting at fault. Never the text of the configuration, a path or a message of
//! Windows: the Event Log is readable by every user of the machine.
//!
//! Until the installer registers a message file for the source, Event Viewer shows the
//! text with a note that the description is missing.

use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
};

/// The source the agent's events are written under.
pub(crate) const SOURCE: &str = "PonteAgent";

/// The text of an event: the kind and the setting, nothing more.
pub(crate) fn text(code: u32, setting: &str, line: Option<usize>) -> String {
    let at = line.map_or(String::new(), |line| format!(", line {line}"));
    format!(
        "The Ponte agent did not start (code {code}): {setting}{at}. See ADR-0011 and ADR-0013."
    )
}

/// Writes an error event. A failure to write it is dropped: there is nowhere left to say so.
pub(crate) fn report(code: u32, text: &str) {
    let source: Vec<u16> = SOURCE.encode_utf16().chain(Some(0)).collect();
    // SAFETY: a null server name is this machine; `source` is NUL-terminated.
    let log = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if log.is_null() {
        return;
    }
    let message: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let strings = [message.as_ptr()];
    // SAFETY: `log` is open; one string, NUL-terminated, alive through the call; no user
    // SID and no binary data.
    unsafe {
        ReportEventW(
            log,
            EVENTLOG_ERROR_TYPE,
            0,
            code,
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        );
        DeregisterEventSource(log);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_names_the_kind_and_the_setting_only() {
        assert_eq!(
            text(1, "manifest_keys", None),
            "The Ponte agent did not start (code 1): manifest_keys. See ADR-0011 and ADR-0013."
        );
        assert_eq!(
            text(1, "the file", Some(3)),
            "The Ponte agent did not start (code 1): the file, line 3. See ADR-0011 and ADR-0013."
        );
    }
}
