use crate::errors::PcwError;
use chrono::prelude::*;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub enum NoteState {
    Constructed,
    Signed,
    Queued,
    Broadcast,
    Seen,
    Confirmed,
    Reissued,
    Cancelled,
    Orphaned,
    Obsolete,
    Conflict,
}

#[derive(Clone, Debug)]
pub enum Event {
    Construct,
    Sign,
    Enqueue,
    Broadcast,
    MempoolAccept,
    ConfirmDepthReached,
    HoldTimeout,
    ExplicitCancel,
    Superseded,
    ExternalConflict,
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
            (&NoteState::Constructed | &NoteState::Signed | &NoteState::Queued | &NoteState::Broadcast | &NoteState::Seen, Event::ExplicitCancel) => Ok(NoteState::Cancelled),
            (_, Event::Superseded) => Ok(NoteState::Obsolete),
            (_, Event::ExternalConflict) => Ok(NoteState::Conflict),
            (NoteState::Confirmed, Event::ReorgOrphan) => Ok(NoteState::Orphaned),
            (NoteState::Orphaned, Event::Broadcast) => Ok(NoteState::Broadcast),
            _ => Err(PcwError::Other("Invalid transition §11.2".to_string())),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum InvoiceState {
    Open,
    FanOutPending,
    Building,
    Ready,
    Broadcasting,
    Closing,
    InsufficientUtxo,
    Expired,
    Stopped,
    Completed,
}

// Similar transition fn for InvoiceState

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_transition() {
        let mut state = NoteState::Constructed;
        state = state.transition(Event::Sign).unwrap();
        assert_eq!(state, NoteState::Signed);
        // etc for paths, reject invalid
    }
}
