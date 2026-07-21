mod id;
mod runtime;
mod runtime_registry;
pub mod state;
mod title;

pub use id::TerminalId;
pub use runtime::TerminalRuntime;
pub(crate) use runtime_registry::TerminalRuntimeRegistry;
pub use state::{
    AgentMetadataReport, EffectivePresentation, EffectiveStateChange, TerminalState,
    TerminalStateMutation, WorkingDuration,
};
pub(crate) use title::stripped_terminal_title;
