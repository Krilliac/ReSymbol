#![forbid(unsafe_code)]

use std::{env, error::Error, fs, io, path::PathBuf};

use wit_component::ComponentEncoder;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let module_path = PathBuf::from(arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: resymbol-example-wasm-componentize <core-module.wasm> <component.wasm>",
        )
    })?);
    let component_path = PathBuf::from(arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: resymbol-example-wasm-componentize <core-module.wasm> <component.wasm>",
        )
    })?);
    if arguments.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected argument").into());
    }

    let module = fs::read(&module_path)?;
    let component = ComponentEncoder::default()
        .module(&module)?
        .validate(true)
        .encode()?;
    fs::write(&component_path, component)?;
    println!("wrote {}", component_path.display());
    Ok(())
}
