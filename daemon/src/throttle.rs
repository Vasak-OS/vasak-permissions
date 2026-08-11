//! A ceiling on how often a person can be asked something.
//!
//! A stored refusal already stops one program from asking about one thing twice.
//! What it does not stop is volume: eleven resources per program, and a program
//! that copies itself to eleven paths gets eleven times that. Somebody who is
//! shown dialogs faster than they can read them stops reading them, which turns
//! every later question into a reflex click — so the ceiling protects the
//! meaning of the answers, not just the screen.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How many questions one person may be asked in `WINDOW`.
///
/// Generous for anything legitimate: an application asks about a resource once
/// in its life, and even a first run that needs camera, microphone and screen
/// stays well inside it.
const LIMIT: usize = 5;
const WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct PromptThrottle {
    /// When each recent prompt was shown, per user, oldest first.
    recent: HashMap<u32, Vec<Instant>>,
}

impl PromptThrottle {
    /// Records that a question is about to be asked, or refuses to let it be.
    ///
    /// Returns `false` when the ceiling is reached. The caller must treat that
    /// as "could not ask" rather than as a refusal from the user: remembering it
    /// would let a burst of noise permanently deny a program the person never
    /// even saw a dialog for.
    pub fn allow(&mut self, uid: u32, now: Instant) -> bool {
        let recent = self.recent.entry(uid).or_default();
        recent.retain(|shown| now.duration_since(*shown) < WINDOW);

        if recent.len() >= LIMIT {
            return false;
        }

        recent.push(now);
        true
    }

    /// Gives back a reserved slot because no dialog was actually shown.
    ///
    /// Without this, a program hammering during login — before the agent has
    /// started, so nothing can be displayed — would use up the allowance, and
    /// the first question that could genuinely have been asked would be turned
    /// away instead.
    pub fn refund(&mut self, uid: u32) {
        if let Some(recent) = self.recent.get_mut(&uid) {
            recent.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handful_of_questions_goes_through() {
        let mut throttle = PromptThrottle::default();
        let now = Instant::now();

        for attempt in 0..LIMIT {
            assert!(throttle.allow(1000, now), "prompt {attempt} should be allowed");
        }
    }

    #[test]
    fn a_flood_is_stopped() {
        let mut throttle = PromptThrottle::default();
        let now = Instant::now();

        for _ in 0..LIMIT {
            assert!(throttle.allow(1000, now));
        }
        assert!(!throttle.allow(1000, now), "the ceiling should hold");
    }

    /// The window slides, so someone who was flooded once is not left unable to
    /// be asked anything for the rest of the session.
    #[test]
    fn the_ceiling_lifts_once_the_window_passes() {
        let mut throttle = PromptThrottle::default();
        let start = Instant::now();

        for _ in 0..LIMIT {
            assert!(throttle.allow(1000, start));
        }
        assert!(!throttle.allow(1000, start));

        let later = start + WINDOW + Duration::from_secs(1);
        assert!(throttle.allow(1000, later));
    }

    /// Half a window later the earliest prompts have expired and the rest have
    /// not, so exactly as many slots free up as fell out.
    #[test]
    fn the_window_expires_prompts_one_at_a_time() {
        let mut throttle = PromptThrottle::default();
        let start = Instant::now();

        // Two early, then the rest a little later.
        assert!(throttle.allow(1000, start));
        assert!(throttle.allow(1000, start));
        let mid = start + Duration::from_secs(30);
        for _ in 2..LIMIT {
            assert!(throttle.allow(1000, mid));
        }
        assert!(!throttle.allow(1000, mid));

        // Past the window for the first two only.
        let after = start + WINDOW + Duration::from_secs(1);
        assert!(throttle.allow(1000, after));
        assert!(throttle.allow(1000, after));
        assert!(!throttle.allow(1000, after), "the later ones still count");
    }

    /// One person being flooded must not stop another from being asked; the
    /// service serves every session on the machine.
    #[test]
    fn one_user_being_flooded_does_not_silence_another() {
        let mut throttle = PromptThrottle::default();
        let now = Instant::now();

        for _ in 0..LIMIT {
            assert!(throttle.allow(1000, now));
        }
        assert!(!throttle.allow(1000, now));

        assert!(throttle.allow(1001, now), "another user is unaffected");
    }

    /// A request that never reached a screen must not use up the allowance.
    #[test]
    fn a_question_that_was_never_shown_gives_its_slot_back() {
        let mut throttle = PromptThrottle::default();
        let now = Instant::now();

        for _ in 0..LIMIT {
            assert!(throttle.allow(1000, now));
            throttle.refund(1000);
        }

        assert!(
            throttle.allow(1000, now),
            "nothing was ever displayed, so nothing should have been spent"
        );
    }

    #[test]
    fn refunding_a_user_with_nothing_pending_is_harmless() {
        let mut throttle = PromptThrottle::default();
        throttle.refund(1000);
        assert!(throttle.allow(1000, Instant::now()));
    }
}
