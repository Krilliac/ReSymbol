use std::{error::Error, fmt, io};

use windows_sys::Win32::{
    Globalization::CP_UTF8,
    System::Console::{SetConsoleCP, SetConsoleOutputCP},
};

/// Failure to select UTF-8 for one side of the current Windows console.
#[derive(Debug)]
pub enum Utf8ConsoleError {
    /// `SetConsoleCP` rejected the UTF-8 input code page.
    Input(io::Error),
    /// `SetConsoleOutputCP` rejected the UTF-8 output code page.
    Output(io::Error),
}

impl fmt::Display for Utf8ConsoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(source) => {
                write!(
                    formatter,
                    "cannot select UTF-8 console input code page: {source}"
                )
            }
            Self::Output(source) => write!(
                formatter,
                "cannot select UTF-8 console output code page: {source}"
            ),
        }
    }
}

impl Error for Utf8ConsoleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Input(source) | Self::Output(source) => Some(source),
        }
    }
}

/// Selects UTF-8 for both input and output on the calling process's console.
///
/// This changes only the attached console. It does not launch a shell or trust
/// an environment-derived executable path. The first rejected Win32 call is
/// returned with its exact input/output stage and operating-system error.
pub fn configure_utf8_console() -> Result<(), Utf8ConsoleError> {
    configure_utf8_console_with(
        |code_page| {
            // SAFETY: `SetConsoleCP` accepts a code-page identifier by value and
            // does not retain pointers or transfer ownership.
            win32_console_result(unsafe { SetConsoleCP(code_page) })
        },
        |code_page| {
            // SAFETY: `SetConsoleOutputCP` accepts a code-page identifier by
            // value and does not retain pointers or transfer ownership.
            win32_console_result(unsafe { SetConsoleOutputCP(code_page) })
        },
    )
}

fn configure_utf8_console_with(
    set_input: impl FnOnce(u32) -> io::Result<()>,
    set_output: impl FnOnce(u32) -> io::Result<()>,
) -> Result<(), Utf8ConsoleError> {
    set_input(CP_UTF8).map_err(Utf8ConsoleError::Input)?;
    set_output(CP_UTF8).map_err(Utf8ConsoleError::Output)
}

fn win32_console_result(succeeded: i32) -> io::Result<()> {
    if succeeded == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Utf8ConsoleError, configure_utf8_console_with};
    use std::{cell::Cell, io};
    use windows_sys::Win32::Globalization::CP_UTF8;

    #[test]
    fn successful_configuration_sets_both_sides_to_utf8() {
        let input = Cell::new(0);
        let output = Cell::new(0);

        configure_utf8_console_with(
            |code_page| {
                input.set(code_page);
                Ok(())
            },
            |code_page| {
                output.set(code_page);
                Ok(())
            },
        )
        .expect("synthetic setters accept UTF-8");

        assert_eq!(input.get(), CP_UTF8);
        assert_eq!(output.get(), CP_UTF8);
    }

    #[test]
    fn input_failure_is_typed_and_short_circuits_output() {
        let output_calls = Cell::new(0);

        let error = configure_utf8_console_with(
            |_| Err(io::Error::from_raw_os_error(1117)),
            |_| {
                output_calls.set(output_calls.get() + 1);
                Ok(())
            },
        )
        .expect_err("synthetic input setter fails");

        assert!(matches!(
            &error,
            Utf8ConsoleError::Input(source) if source.raw_os_error() == Some(1117)
        ));
        assert!(
            error
                .to_string()
                .starts_with("cannot select UTF-8 console input code page:")
        );
        assert_eq!(output_calls.get(), 0);
    }

    #[test]
    fn output_failure_is_typed_after_input_succeeds() {
        let input_calls = Cell::new(0);

        let error = configure_utf8_console_with(
            |_| {
                input_calls.set(input_calls.get() + 1);
                Ok(())
            },
            |_| Err(io::Error::from_raw_os_error(87)),
        )
        .expect_err("synthetic output setter fails");

        assert!(matches!(
            &error,
            Utf8ConsoleError::Output(source) if source.raw_os_error() == Some(87)
        ));
        assert!(
            error
                .to_string()
                .starts_with("cannot select UTF-8 console output code page:")
        );
        assert_eq!(input_calls.get(), 1);
    }
}
