//! Module for failure handling and state management in the PCW-1 protocol.
//!
//! This module defines state machines for notes and invoices, including transition
//! logic as per §11, to handle failures, reissues, and cancellations deterministically.

use crate::errors::PcwError;

/// Represents the state of a single note in the protocol (§11.2).
#[derive(Clone, Debug, PartialEq)]
pub enum NoteState {
    /// Note has been constructed but not signed.
    Constructed,
    /// Note has been signed but not queued.
    Signed,
    /// Note is queued for broadcast.
    Queued,
    /// Note has been broadcast to the network.
    Broadcast,
    /// Note is seen in the mempool.
    Seen,
    /// Note has reached the required confirmation depth.
    Confirmed,
    /// Note has been reissued due to a hold timeout.
    Reissued,
    /// Note has been explicitly cancelled.
    Cancelled,
    /// Note has been orphaned due to a reorg.
    Orphaned,
    /// Note is obsolete due to a superseded transaction.
    Obsolete,
    /// Note is in conflict due to an external spend.
    Conflict,
}

/// Represents events that trigger state transitions for a note (§11.2).
#[derive(Clone, Debug)]
pub enum Event {
    /// Note construction initiated.
    Construct,
    /// Note signed with valid keys.
    Sign,
    /// Note enqueued for broadcast.
    Enqueue,
    /// Note broadcast to the network.
    Broadcast,
    /// Note accepted into the mempool.
    MempoolAccept,
    /// Note reached the required confirmation depth.
    ConfirmDepthReached,
    /// Note hold timeout occurred.
    HoldTimeout,
    /// Note explicitly cancelled by user/policy.
    ExplicitCancel,
    /// Note superseded by a newer version.
    Superseded,
    /// Note conflicted by an external spend.
    ExternalConflict,
    /// Note orphaned due to a blockchain reorg.
    ReorgOrphan,
}

impl NoteState {
    /// Transition per §11.2 diagram, enforcing invariants.
    pub fn transition(&self, event: Event) -> Result<Self, PcwError> {
        match (self, event) {
            (NoteState::Constructed, Event::Sign) => Ok(NoteState::Signed),
            (NoteState::Signed, Event::Enqueue) => Ok(NoteState::Queued),
            (NoteState::Queued, Event::Broadcast) => Ok(NoteState::Broadcast),
            (NoteState::Broadcast, Event::MempoolAccept) => Ok(NoteState::Seen),
            (NoteState::Seen, Event::ConfirmDepthReached) => Ok(NoteState::Confirmed),
            (NoteState::Queued, Event::HoldTimeout) => Ok(NoteState::Reissued),
            (s, Event::ExplicitCancel)
                if matches!(
                    s,
                    NoteState::Constructed
                        | NoteState::Signed
                        | NoteState::Queued
                        | NoteState::Broadcast
                        | NoteState::Seen
                ) =>
            {
                Ok(NoteState::Cancelled)
            }
            (_, Event::Superseded) => Ok(NoteState::Obsolete),
            (_, Event::ExternalConflict) => Ok(NoteState::Conflict),
            (NoteState::Confirmed, Event::ReorgOrphan) => Ok(NoteState::Orphaned),
            (NoteState::Orphaned, Event::Broadcast) => Ok(NoteState::Broadcast),
            _ => Err(PcwError::Other("Invalid transition §11.2".to_string())),
        }
    }
}

/// Represents the state of an invoice in the protocol (§11.2).
#[derive(Clone, Debug, PartialEq)]
pub enum InvoiceState {
    /// Invoice is open and awaiting construction.
    Open,
    /// Invoice is pending a fan-out attempt.
    FanOutPending,
    /// Invoice is being built with notes.
    Building,
    /// Invoice is ready for broadcasting.
    Ready,
    /// Invoice is in the process of broadcasting.
    Broadcasting,
    /// Invoice is closing after completion.
    Closing,
    /// Invoice failed due to insufficient UTXOs.
    InsufficientUtxo,
    /// Invoice has expired.
    Expired,
    /// Invoice has been stopped manually.
    Stopped,
    /// Invoice is fully completed.
    Completed,
}

impl InvoiceState {
    /// Transition per §11.2 diagram, enforcing invariants.
    pub fn transition(&self, event: Event) -> Result<Self, PcwError> {
        match (self, event) {
            (InvoiceState::Open, Event::Construct) => Ok(InvoiceState::FanOutPending),
            (InvoiceState::FanOutPending, Event::Sign) => Ok(InvoiceState::Building),
            (InvoiceState::Building, Event::Enqueue) => Ok(InvoiceState::Ready),
            (InvoiceState::Ready, Event::Broadcast) => Ok(InvoiceState::Broadcasting),
            (InvoiceState::Broadcasting, Event::MempoolAccept) => Ok(InvoiceState::Closing),
            (InvoiceState::Closing, Event::ConfirmDepthReached) => Ok(InvoiceState::Completed),
            (InvoiceState::FanOutPending, Event::HoldTimeout) => Ok(InvoiceState::InsufficientUtxo),
            (s, Event::ExplicitCancel)
                if matches!(
                    s,
                    InvoiceState::Open
                        | InvoiceState::FanOutPending
                        | InvoiceState::Building
                        | InvoiceState::Ready
                        | InvoiceState::Broadcasting
                ) =>
            {
                Ok(InvoiceState::Stopped)
            }
            (_, Event::Superseded) => Ok(InvoiceState::Expired),
            (_, Event::ExternalConflict) => Ok(InvoiceState::Expired),
            (InvoiceState::Completed, Event::ReorgOrphan) => Ok(InvoiceState::Broadcasting),
            _ => Err(PcwError::Other("Invalid transition §11.2".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_transition() {
        let mut state = NoteState::Constructed;
        state = state.transition(Event::Sign).unwrap();
        assert_eq!(state, NoteState::Signed);

        state = state.transition(Event::Enqueue).unwrap();
        assert_eq!(state, NoteState::Queued);

        state = state.transition(Event::Broadcast).unwrap();
        assert_eq!(state, NoteState::Broadcast);

        assert!(state.transition(Event::Sign).is_err()); // Invalid transition
    }

    #[test]
    fn test_invoice_transition() {
        let mut state = InvoiceState::Open;
        state = state.transition(Event::Construct).unwrap();
        assert_eq!(state, InvoiceState::FanOutPending);

        state = state.transition(Event::Sign).unwrap();
        assert_eq!(state, InvoiceState::Building);

        state = state.transition(Event::Enqueue).unwrap();
        assert_eq!(state, InvoiceState::Ready);

        assert!(state.transition(Event::Construct).is_err()); // Invalid transition
    }
}
