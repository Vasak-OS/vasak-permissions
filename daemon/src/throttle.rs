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

#[derive(Debug, Default)]
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

/// A ceiling on how often the same block is announced to the same person.
///
/// Distinto del de arriba y por otro motivo. `PromptThrottle` protege el
/// significado de las respuestas; esto protege el aviso de sí mismo: un punto
/// que hace cumplir un permiso ve al mismo programa **en cada conexión** —el
/// módulo de WirePlumber lo ve cada vez que un cliente se conecta— y sin techo
/// un navegador que abre tres conexiones produce tres avisos idénticos.
///
/// Se recuerda por persona, programa y recurso, que es exactamente lo que el
/// aviso dice. Dos programas distintos, o el mismo pidiendo dos cosas, son
#[derive(Debug, Default)]
pub struct NoticeThrottle {
    shown: HashMap<(u32, String, String), Instant>,
}

/// Cuánto se calla un aviso repetido del mismo programa y el mismo recurso.
///
/// El mismo valor que usa el camino de AppArmor, y por la misma razón: una
/// aplicación a la que se le niega la cámara suele reintentar en bucle.
const NOTICE_SILENCE: Duration = Duration::from_secs(300);

impl NoticeThrottle {
    /// Whether this block should be announced now, and records that it was.
    pub fn should_notify(
        &mut self,
        uid: u32,
        binary_path: &str,
        resource_id: &str,
        now: Instant,
    ) -> bool {
        // Que el mapa no crezca sin techo en una sesión larga.
        self.shown
            .retain(|_, shown| now.duration_since(*shown) < NOTICE_SILENCE);

        let key = (uid, binary_path.to_string(), resource_id.to_string());
        if self.shown.contains_key(&key) {
            return false;
        }
        self.shown.insert(key, now);
        true
    }
}

/// Un techo sobre cada cuánto una aplicación puede volver a pedirse **a sí
/// misma** un permiso.
///
/// Distinto de los otros dos y por otro motivo. `RequestAgain` no pasa por
/// polkit —el sentido es que la aplicación se re-pida sola, detrás de un botón—,
/// así que sin este techo sería una forma de reabrir el diálogo una y otra vez
/// hasta que la persona ceda de cansada: justo la fatiga de permisos que
/// `ForgetPermission` evita quedándose detrás de polkit. Un programa recién
/// denegado no tiene por qué volver a preguntar al segundo; una persona que de
/// verdad quiere reintentar puede esperar [`REASK_COOLDOWN`].
///
/// Se recuerda por persona, programa y recurso: que una aplicación se re-pida la
/// cámara no puede callar su re-pedido del micrófono, ni el de otra aplicación,
/// ni el de otra sesión.
#[derive(Default)]
pub struct ReaskThrottle {
    last: HashMap<(u32, String, String), Instant>,
}

/// Cuánto tiene que pasar entre dos «pedir de nuevo» del mismo programa por el
/// mismo recurso.
///
/// Un minuto: alto como para que una aplicación no pueda machacar el diálogo, y
/// bajo como para que alguien que denegó por error y quiere reintentar no quede
/// trabado. Lo elige este archivo a propósito, para que ajustarlo sea un solo
/// cambio y la revisión de seguridad tenga dónde mirarlo.
const REASK_COOLDOWN: Duration = Duration::from_secs(60);

impl ReaskThrottle {
    /// Si se puede volver a pedir ahora. Anota el momento **sólo cuando devuelve
    /// `true`**: un intento rechazado no corre el reloj, así que la ventana se
    /// mide desde el último re-pedido que de verdad ocurrió y no se puede estirar
    /// a fuerza de insistir.
    pub fn allow(&mut self, uid: u32, binary_path: &str, resource_id: &str, now: Instant) -> bool {
        // Que el mapa no crezca sin techo en una sesión larga; de paso saca lo
        // que ya cumplió el enfriamiento.
        self.last
            .retain(|_, when| now.duration_since(*when) < REASK_COOLDOWN);

        let key = (uid, binary_path.to_string(), resource_id.to_string());
        if self.last.contains_key(&key) {
            return false;
        }
        self.last.insert(key, now);
        true
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
            assert!(
                throttle.allow(1000, now),
                "prompt {attempt} should be allowed"
            );
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

    /// El caso que lo justifica: un navegador que abre varias conexiones a
    /// PipeWire una detrás de otra.
    #[test]
    fn el_mismo_bloqueo_seguido_avisa_una_sola_vez() {
        let mut techo = NoticeThrottle::default();
        let ahora = Instant::now();

        assert!(techo.should_notify(1000, "/usr/bin/navegador", "camera", ahora));
        assert!(!techo.should_notify(1000, "/usr/bin/navegador", "camera", ahora));
        assert!(!techo.should_notify(
            1000,
            "/usr/bin/navegador",
            "camera",
            ahora + Duration::from_secs(60)
        ));
    }

    #[test]
    fn pasado_el_silencio_vuelve_a_avisar() {
        let mut techo = NoticeThrottle::default();
        let ahora = Instant::now();

        assert!(techo.should_notify(1000, "/usr/bin/navegador", "camera", ahora));
        assert!(techo.should_notify(
            1000,
            "/usr/bin/navegador",
            "camera",
            ahora + NOTICE_SILENCE + Duration::from_secs(1)
        ));
    }

    /// Callar un aviso no puede callar otro: son hechos distintos y cada uno
    /// lleva su oferta de permitir.
    #[test]
    fn otro_programa_u_otro_recurso_avisan_igual() {
        let mut techo = NoticeThrottle::default();
        let ahora = Instant::now();

        assert!(techo.should_notify(1000, "/usr/bin/navegador", "camera", ahora));
        assert!(techo.should_notify(1000, "/usr/bin/otro", "camera", ahora));
        assert!(techo.should_notify(1000, "/usr/bin/navegador", "microphone", ahora));
        assert!(techo.should_notify(1001, "/usr/bin/navegador", "camera", ahora));
    }

    /// El caso que justifica el techo de re-pedidos: un re-pedido pasa y el
    /// siguiente, seguido, no. Sin esto un botón «pedir de nuevo» sería una
    /// forma de abrir el diálogo a repetición.
    #[test]
    fn un_re_pedido_pasa_y_el_siguiente_seguido_no() {
        let mut techo = ReaskThrottle::default();
        let ahora = Instant::now();

        assert!(techo.allow(1000, "/usr/bin/vasak-mail", "account.email", ahora));
        assert!(!techo.allow(1000, "/usr/bin/vasak-mail", "account.email", ahora));
    }

    /// Pasado el enfriamiento se puede volver a pedir.
    #[test]
    fn pasado_el_enfriamiento_vuelve_a_pasar() {
        let mut techo = ReaskThrottle::default();
        let ahora = Instant::now();

        assert!(techo.allow(1000, "/usr/bin/vasak-mail", "account.email", ahora));
        assert!(techo.allow(
            1000,
            "/usr/bin/vasak-mail",
            "account.email",
            ahora + REASK_COOLDOWN
        ));
    }

    /// Un intento cortado no corre el reloj: la ventana se mide desde el último
    /// re-pedido que de verdad ocurrió, no desde el que se rechazó. Si corriera,
    /// una aplicación insistente podría estirar su propio enfriamiento para
    /// siempre y nunca dejar pasar el próximo que sí correspondía.
    #[test]
    fn un_intento_cortado_no_corre_el_reloj() {
        let mut techo = ReaskThrottle::default();
        let inicio = Instant::now();

        assert!(techo.allow(1000, "/usr/bin/vasak-mail", "account.email", inicio));
        // A mitad del enfriamiento se insiste y se corta.
        assert!(!techo.allow(
            1000,
            "/usr/bin/vasak-mail",
            "account.email",
            inicio + Duration::from_secs(40)
        ));
        // Al cumplirse el enfriamiento desde el **primero**, vuelve a pasar. Si
        // el intento cortado hubiera corrido el reloj, acá todavía estaría
        // bloqueado.
        assert!(techo.allow(
            1000,
            "/usr/bin/vasak-mail",
            "account.email",
            inicio + REASK_COOLDOWN
        ));
    }

    /// Callar un re-pedido no puede callar otro: otro recurso, otro programa u
    /// otra persona se piden igual.
    #[test]
    fn otro_recurso_programa_o_persona_no_se_callan() {
        let mut techo = ReaskThrottle::default();
        let ahora = Instant::now();

        assert!(techo.allow(1000, "/usr/bin/vasak-mail", "account.email", ahora));
        assert!(techo.allow(1000, "/usr/bin/vasak-mail", "camera", ahora));
        assert!(techo.allow(1000, "/usr/bin/vasak-calendar", "account.email", ahora));
        assert!(techo.allow(1001, "/usr/bin/vasak-mail", "account.email", ahora));
    }
}
