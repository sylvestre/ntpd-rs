//! This crate contains packet parsing and algorithm code for ntpd-rs and is not
//! intended as a public interface at this time. It follows the same version as the
//! main ntpd-rs crate, but that version is not intended to give any stability
//! guarantee. Use at your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.
#![forbid(unsafe_code)]

mod algorithm;
mod arrayvec;
mod clock;
mod config;
mod cookiestash;
mod identifiers;
mod keyset;
mod nts_record;
mod packet;
mod peer;
mod system;
mod time_types;

#[cfg(feature = "fuzz")]
pub use algorithm::fuzz_find_interval;
pub use algorithm::{
    DefaultTimeSyncController, ObservablePeerTimedata, StandardClockController, StateUpdate,
    TimeSyncController,
};
pub use clock::NtpClock;
pub use config::{StepThreshold, SystemConfig};
pub use identifiers::ReferenceId;
pub use keyset::{DecodedServerCookie, KeySet, KeySetProvider};

#[cfg(feature = "fuzz")]
pub use keyset::test_cookie;
#[cfg(feature = "fuzz")]
pub use packet::ExtensionField;
pub use packet::{
    Cipher, CipherProvider, NoCipher, NtpAssociationMode, NtpLeapIndicator, NtpPacket,
};
#[cfg(feature = "fuzz")]
pub use peer::fuzz_measurement_from_packet;
#[cfg(feature = "ext-test")]
pub use peer::peer_snapshot;
pub use peer::{
    AcceptSynchronizationError, IgnoreReason, Measurement, Peer, PeerNtsData, PeerSnapshot,
    PollError, Reach, Update,
};
pub use system::{SystemSnapshot, TimeSnapshot};
#[cfg(feature = "fuzz")]
pub use time_types::fuzz_duration_from_seconds;
pub use time_types::{
    FrequencyTolerance, NtpDuration, NtpInstant, NtpTimestamp, PollInterval, PollIntervalLimits,
};

#[cfg(feature = "fuzz")]
pub use nts_record::fuzz_key_exchange_result_decoder;
#[cfg(feature = "fuzz")]
pub use nts_record::fuzz_key_exchange_server_decoder;
pub use nts_record::{
    KeyExchangeClient, KeyExchangeError, KeyExchangeResult, KeyExchangeServer, NtsRecord,
    NtsRecordDecoder, WriteError,
};

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    pub const SOFTWARE: i32 = 70;

    /// You did not have sufficient permission to perform
    /// the operation.  This is not intended for file system
    /// problems, which should use `NOINPUT` or `CANTCREAT`,
    /// but rather for higher level permissions.
    pub const NOPERM: i32 = 77;
}
