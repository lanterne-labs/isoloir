//! The isoloir services: the ingest (relays → judge → log → checkpoints →
//! mirror), the authority (replay → decrypt → tally), their storage and
//! their sources of the log.

pub mod direct;
pub mod eligibility;
pub mod ingest;
pub mod mirror;
pub mod relays;
pub mod source;
pub mod store;
pub mod authority;

/// The OpenTimestamps calendars the ingest submits to.
pub fn stamps_calendars() -> Vec<String> {
    isoloir_stamps::default_calendars()
}
