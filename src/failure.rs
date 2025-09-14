//! Module for failure handling and state transitions in the PCW-1 protocol.
//!
//! This module implements the state machines for notes and invoices as per §11,
//! including `NoteState` for individual note transaction states and `InvoiceState`
//! for invoice-level states. It also defines `Event` for logging state changes.
use crate::errors::PcwError;
use serde::{Deserialize, Serialize};

/// Note state per §11.2: State machine for note transactions.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NoteState {
    Signed,
    Broadcast,
    Confirmed,
    ReorgOrphan,
    Superseded,
}

impl NoteState {
    /// Transition to a new state based on an event (§11.2).
    pub fn transition(&self, event: &Event) -> Result<Self, PcwError> {
        match (self, event) {
            (NoteState::Signed, Event::Broadcast) => Ok(NoteState::Broadcast),
            (NoteState::Broadcast, Event::Confirm) => Ok(NoteState::Confirmed),
            (NoteState::Broadcast, Event::Reorg) => Ok(NoteState::ReorgOrphan),
            (NoteState::Broadcast, Event::Supersede) => Ok(NoteState::Superseded),
            (NoteState::Confirmed, Event::Reorg) => Ok(NoteState::ReorgOrphan),
            (NoteState::Confirmed, Event::Supersede) => Ok(NoteState::Superseded),
            _ => Err(PcwError::Other(format!(
                "Invalid note state transition from {:?} with event {:?} §11.2",
                self, event
            ))),
        }
    }
}

/// Invoice state per §11.2: State machine for invoices.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum InvoiceState {
    Draft,
    Signed,
    Broadcast,
    Confirmed,
    Failed,
}

impl InvoiceState {
    /// Transition to a new state based on an event (§11.2).
    pub fn transition(&self, event: &Event) -> Result<Self, PcwError> {
        match (self, event) {
            (InvoiceState::Draft, Event::Sign) => Ok(InvoiceState::Signed),
            (InvoiceState::Signed, Event::Broadcast) => Ok(InvoiceState::Broadcast),
            (InvoiceState::Broadcast, Event::Confirm) => Ok(InvoiceState::Confirmed),
            (InvoiceState::Broadcast, Event::Fail) => Ok(InvoiceState::Failed),
            (InvoiceState::Confirmed, Event::Fail) => Ok(InvoiceState::Failed),
            _ => Err(PcwError::Other(format!(
                "Invalid invoice state transition from {:?} with event {:?} §11.2",
                self, event
            ))),
        }
    }
}

/// Event triggering state transitions (§11.2).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Event {
    Sign,
    Broadcast,
    Confirm,
    Reorg,
    Supersede,
    Fail,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::canonical_json;

    #[test]
    fn test_note_state_transitions() -> Result<(), PcwError> {
        let mut state = NoteState::Signed;
        // Valid transitions
        state = state.transition(&Event::Broadcast)?;
        assert_eq!(state, NoteState::Broadcast);
        state = state.transition(&Event::Confirm)?;
        assert_eq!(state, NoteState::Confirmed);
        state = state.transition(&Event::Reorg)?;
        assert_eq!(state, NoteState::ReorgOrphan);
        // Reset and test Superseded
        state = NoteState::Broadcast;
        state = state.transition(&Event::Supersede)?;
        assert_eq!(state, NoteState::Superseded);
        // Invalid transition
        let result = NoteState::Signed.transition(&Event::Supersede);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid note state transition")));
        Ok(())
    }

    #[test]
    fn test_invoice_state_transitions() -> Result<(), PcwError> {
        let mut state = InvoiceState::Draft;
        // Valid transitions
        state = state.transition(&Event::Sign)?;
        assert_eq!(state, InvoiceState::Signed);
        state = state.transition(&Event::Broadcast)?;
        assert_eq!(state, InvoiceState::Broadcast);
        state = state.transition(&Event::Confirm)?;
        assert_eq!(state, InvoiceState::Confirmed);
        state = state.transition(&Event::Fail)?;
        assert_eq!(state, InvoiceState::Failed);
        // Reset and test Broadcast to Failed
        state = InvoiceState::Broadcast;
        state = state.transition(&Event::Fail)?;
        assert_eq!(state, InvoiceState::Failed);
        // Invalid transition
        let result = InvoiceState::Draft.transition(&Event::Confirm);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid invoice state transition")));
        Ok(())
    }

    #[test]
    fn test_event_serialization() -> Result<(), PcwError> {
        let event = Event::Sign;
        let serialized = canonical_json(&event)?;
        assert_eq!(serialized, b"\"Sign\"");
        let event = Event::Supersede;
        let serialized = canonical_json(&event)?;
        assert_eq!(serialized, b"\"Supersede\"");
        Ok(())
    }

    #[test]
    fn test_note_state_invalid_transitions() -> Result<(), PcwError> {
        // Test all invalid transitions for NoteState
        let invalid_transitions = [
            (NoteState::Signed, Event::Sign),
            (NoteState::Signed, Event::Confirm),
            (NoteState::Signed, Event::Reorg),
            (NoteState::Signed, Event::Fail),
            (NoteState::Broadcast, Event::Sign),
            (NoteState::Broadcast, Event::Fail),
            (NoteState::Confirmed, Event::Sign),
            (NoteState::Confirmed, Event::Broadcast),
            (NoteState::Confirmed, Event::Confirm),
            (NoteState::ReorgOrphan, Event::Sign),
            (NoteState::ReorgOrphan, Event::Broadcast),
            (NoteState::ReorgOrphan, Event::Confirm),
            (NoteState::ReorgOrphan, Event::Reorg),
            (NoteState::ReorgOrphan, Event::Supersede),
            (NoteState::ReorgOrphan, Event::Fail),
            (NoteState::Superseded, Event::Sign),
            (NoteState::Superseded, Event::Broadcast),
            (NoteState::Superseded, Event::Confirm),
            (NoteState::Superseded, Event::Reorg),
            (NoteState::Superseded, Event::Supersede),
            (NoteState::Superseded, Event::Fail),
        ];
        for (state, event) in invalid_transitions {
            let result = state.transition(&event);
            assert!(result.is_err());
            assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid note state transition")));
        }
        Ok(())
    }

    #[test]
    fn test_invoice_state_invalid_transitions() -> Result<(), PcwError> {
        // Test all invalid transitions for InvoiceState
        let invalid_transitions = [
            (InvoiceState::Draft, Event::Broadcast),
            (InvoiceState::Draft, Event::Confirm),
            (InvoiceState::Draft, Event::Reorg),
            (InvoiceState::Draft, Event::Supersede),
            (InvoiceState::Draft, Event::Fail),
            (InvoiceState::Signed, Event::Sign),
            (InvoiceState::Signed, Event::Confirm),
            (InvoiceState::Signed, Event::Reorg),
            (InvoiceState::Signed, Event::Supersede),
            (InvoiceState::Signed, Event::Fail),
            (InvoiceState::Broadcast, Event::Sign),
            (InvoiceState::Broadcast, Event::Reorg),
            (InvoiceState::Broadcast, Event::Supersede),
            (InvoiceState::Confirmed, Event::Sign),
            (InvoiceState::Confirmed, Event::Broadcast),
            (InvoiceState::Confirmed, Event::Confirm),
            (InvoiceState::Confirmed, Event::Reorg),
            (InvoiceState::Confirmed, Event::Supersede),
            (InvoiceState::Failed, Event::Sign),
            (InvoiceState::Failed, Event::Broadcast),
            (InvoiceState::Failed, Event::Confirm),
            (InvoiceState::Failed, Event::Reorg),
            (InvoiceState::Failed, Event::Supersede),
            (InvoiceState::Failed, Event::Fail),
        ];
        for (state, event) in invalid_transitions {
            let result = state.transition(&event);
            assert!(result.is_err());
            assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid invoice state transition")));
        }
        Ok(())
    }
}
