//! Security Director Cloud MCP server composition.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod http_transport;
mod server;

pub use http_transport::serve_http;
pub use server::{KNOWN_TOOLS, SdcHandler, WRITE_TOOLS};
