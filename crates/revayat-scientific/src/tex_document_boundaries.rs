//! Constant-space document-marker effects for provisionally collected headers.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    Preamble,
    Body,
    Ended,
}

#[derive(Clone, Copy)]
pub(super) enum Marker {
    Begin,
    End,
}

impl State {
    pub fn observe(&mut self, marker: Marker) {
        *self = match (*self, marker) {
            (Self::Preamble, Marker::Begin) => Self::Body,
            (Self::Body, Marker::End) => Self::Ended,
            _ => *self,
        };
    }

    pub fn ended(self) -> bool {
        self == Self::Ended
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Deferred {
    outcomes: [State; 2],
}

impl Default for Deferred {
    fn default() -> Self {
        Self {
            outcomes: [State::Preamble, State::Body],
        }
    }
}

impl Deferred {
    pub fn observe(&mut self, marker: Marker) {
        for outcome in &mut self.outcomes {
            outcome.observe(marker);
        }
    }

    pub fn apply(self, state: &mut State) {
        *state = match state {
            State::Preamble => self.outcomes[0],
            State::Body => self.outcomes[1],
            State::Ended => State::Ended,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_markers_preserve_order_and_composition_for_every_initial_state() {
        // Enumerate all words through eight markers and every return seam.
        for length in 0..=8 {
            for word in 0..(1usize << length) {
                let markers: Vec<_> = (0..length)
                    .map(|index| {
                        if word & (1 << index) == 0 {
                            Marker::Begin
                        } else {
                            Marker::End
                        }
                    })
                    .collect();
                let mut whole = Deferred::default();
                for &marker in &markers {
                    whole.observe(marker);
                }
                for initial in [State::Preamble, State::Body, State::Ended] {
                    let mut expected = initial;
                    for &marker in &markers {
                        expected.observe(marker);
                    }
                    let mut actual = initial;
                    whole.apply(&mut actual);
                    assert_eq!(actual, expected, "{length}/{word}/{initial:?}");
                    for split in 0..=length {
                        let mut prefix = Deferred::default();
                        for &marker in &markers[..split] {
                            prefix.observe(marker);
                        }
                        let mut suffix = Deferred::default();
                        for &marker in &markers[split..] {
                            suffix.observe(marker);
                        }
                        let mut composed = initial;
                        prefix.apply(&mut composed);
                        suffix.apply(&mut composed);
                        assert_eq!(composed, expected, "{length}/{word}/{split}/{initial:?}");
                    }
                }
            }
        }
        assert!(std::mem::size_of::<Deferred>() <= 2 * std::mem::size_of::<State>());
    }
}
