//! Security Director Cloud MCP server composition.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod http_transport;
mod server;
mod signals;

pub use http_transport::{build_http_router, serve_http};
pub use server::{DeviceGroupListArgs, KNOWN_TOOLS, SCOPED_READ_TOOLS, SdcHandler, WRITE_TOOLS};
pub use signals::install_sighup_handler;
