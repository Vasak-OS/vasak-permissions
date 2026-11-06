//! La capa de política del cortafuegos: decide **qué pids enrolar** desde la
//! política del usuario, y cablea el conector de procesos y la pantalla de
//! Configuración al mapa BPF (M0 del #93, PR2).
//!
//! # Qué separa este módulo
//!
//! Lo testeable sin root vive en las funciones puras —[`decidir`], y la
//! contabilidad de [`super::Enforcer`]— y se prueba con el motor de mentira. El
//! I/O privilegiado —leer `/proc` para resolver el uid real y el ejecutable de
//! un pid, tomar el candado del enforcer— queda como adapter fino acá. Por eso
//! `decidir` no toca nada y `atender_evento` sólo la envuelve con la lectura.
//!
//! # F3 — se clava por uid **real**
//!
//! El programa BPF lee `bpf_get_current_uid_gid()`, que es el uid **real** del
//! syscall. Así que al enrolar un pid se usa su uid real
//! ([`crate::procesos::uid_real_de`], el primer campo de `Uid:` en
//! `/proc/<pid>/status`), nunca el efectivo ni el dueño de `/proc/<pid>/exe`: un
//! binario setuid o un proceso que cambió su uid real tiene que seguir cortado,
//! y con la clave equivocada se escaparía sin que nada falle.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::{Enforcer, MotorAya, MotorBpf};

/// Lo que el conector de procesos observó de un pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evento {
    /// `exec`: el proceso cambió de ejecutable; se reevalúa de cero.
    Exec,
    /// `fork`: nació un hijo. Hereda el ejecutable del padre hasta que haga
    /// `exec`, así que evaluar su propio `/proc/<pid>/exe` (== el del padre) es
    /// la herencia de política por árbol que pide el diseño.
    Fork,
    /// `exit`: el proceso salió; su marca se limpia.
    Exit,
}

/// Qué hacer con un pid ante un evento, según si su ejecutable está cortado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accion {
    Bloquear,
    Limpiar,
    Nada,
}

/// La regla pura, sin tocar `/proc` ni el mapa: dado el evento y si el
/// ejecutable del pid está cortado, qué corresponde.
///
/// - `exec`: reevaluar. Cortado → marcar; no cortado → limpiar, por si el pid
///   venía marcado de un ejecutable anterior (re-exec del mismo número).
/// - `fork`: cortado → marcar (herencia del árbol); no cortado → nada, un hijo
///   recién nacido no tenía marca que limpiar.
/// - `exit`: limpiar siempre, pase lo que pase con el ejecutable.
pub fn decidir(evento: Evento, cortado: bool) -> Accion {
    match evento {
        Evento::Exec => {
            if cortado {
                Accion::Bloquear
            } else {
                Accion::Limpiar
            }
        }
        Evento::Fork => {
            if cortado {
                Accion::Bloquear
            } else {
                Accion::Nada
            }
        }
        Evento::Exit => Accion::Limpiar,
    }
}

/// El cortafuegos cargado, compartido entre el conector de procesos (un hilo) y
/// la pantalla de Configuración (el servicio async). `None` cuando no se pudo
/// cargar: el daemon lo registró ruidoso al arrancar y acá no se hace nada.
///
/// `Mutex` de `std` y no de tokio porque `block`/`unblock` son syscalls cortas y
/// sincrónicas; el candado nunca se sostiene a través de un `.await` (el barrido
/// de `/proc` del servicio corre en `spawn_blocking`).
pub type EnforcerCompartido = Arc<Mutex<Option<Enforcer>>>;

/// `uid → {ejecutables con la red cortada}`. Es lo que el conector consulta por
/// cada `exec`/`fork`: una búsqueda barata, sin leer la política del disco en el
/// camino caliente. Lo arma el arranque y lo mantiene `SetPermission(network)`.
pub type RedCortada = Arc<Mutex<HashMap<u32, HashSet<String>>>>;

/// El cortafuegos y el conjunto de red cortada, juntos para pasarlos de una vez
/// al conector y al servicio. Los dos son `Arc`, así que clonarlo comparte.
///
/// Genérico sobre [`MotorBpf`] —con `MotorAya` por omisión, que es lo que usa el
/// daemon— para que los adapters que lo reciben (`atender_evento`,
/// `resincronizar`) se puedan probar con el cortafuegos de mentira.
pub struct Contexto<M: MotorBpf = MotorAya> {
    pub enforcer: Arc<Mutex<Option<Enforcer<M>>>>,
    pub red: RedCortada,
    /// La política de bloqueo por dominio (M2): `uid → binary → {dominios}`. La
    /// consulta `atender_evento` en cada exec/fork para enrolar los pids de un
    /// binario con regla de dominio.
    pub dominios: super::dominio::DominiosBloqueados,
    /// El snoop de DNS (M2): `(uid, IP) → dominio`. De acá salen las IPs a cortar
    /// para un dominio bloqueado. El daemon nunca resuelve, sólo observa.
    pub dns: super::dns::ModeloDnsCompartido,
}

// `Clone` a mano: `#[derive(Clone)]` exigiría `M: Clone`, y el enforcer no lo es
// —vive detrás de un `Arc`, que sí se clona—.
impl<M: MotorBpf> Clone for Contexto<M> {
    fn clone(&self) -> Self {
        Self {
            enforcer: Arc::clone(&self.enforcer),
            red: Arc::clone(&self.red),
            dominios: Arc::clone(&self.dominios),
            dns: Arc::clone(&self.dns),
        }
    }
}

/// Si el ejecutable `binary` está cortado para `uid`.
pub fn esta_cortado(red: &RedCortada, uid: u32, binary: &str) -> bool {
    red.lock()
        .map(|m| m.get(&uid).is_some_and(|s| s.contains(binary)))
        .unwrap_or(false)
}

/// Prende o apaga el corte de un ejecutable para un uid en el conjunto. Lo llama
/// `SetPermission(network)` tras guardar la política, para que los `exec`
/// futuros ya vean el cambio sin releer el disco.
pub fn fijar(red: &RedCortada, uid: u32, binary: &str, cortado: bool) {
    let Ok(mut m) = red.lock() else { return };
    if cortado {
        m.entry(uid).or_default().insert(binary.to_string());
    } else if let Some(set) = m.get_mut(&uid) {
        set.remove(binary);
        if set.is_empty() {
            m.remove(&uid);
        }
    }
}

/// El uid real y el ejecutable canonicalizado de un pid vivo, o `None` si ya no
/// está. El ejecutable se canonicaliza para que coincida con la ruta que guarda
/// la política (que también la canonicaliza en `PinnedCaller`).
pub(crate) fn identidad_de(pid: u32) -> Option<(u32, String)> {
    let uid = crate::procesos::uid_real_de(pid)?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    Some((uid, exe.to_string_lossy().into_owned()))
}

/// Aplica una acción sobre el enforcer compartido, registrando ruidoso cualquier
/// fallo (fail-closed: un corte que no se pudo aplicar no pasa en silencio).
fn aplicar<M: MotorBpf>(ctx: &Contexto<M>, accion: Accion, uid: u32, pid: u32) {
    if accion == Accion::Nada {
        return;
    }
    let Ok(mut guard) = ctx.enforcer.lock() else {
        return;
    };
    let Some(enf) = guard.as_mut() else {
        return; // el cortafuegos no se cargó; ya se avisó al arrancar
    };
    let resultado = match accion {
        Accion::Bloquear => enf.bloquear(uid, pid),
        Accion::Limpiar => enf.limpiar(pid),
        Accion::Nada => return,
    };
    if let Err(e) = resultado {
        tracing::error!("Cortafuegos: {e}");
    }
}

/// Atiende un evento del conector: resuelve la identidad del pid (salvo en
/// `exit`, donde ya no está y el uid sale de lo anotado) y aplica la acción.
pub fn atender_evento<M: MotorBpf>(ctx: &Contexto<M>, evento: Evento, pid: u32) {
    if evento == Evento::Exit {
        // No se lee `/proc`: el proceso ya no está. `limpiar` reconstruye la
        // clave con el uid que anotó al marcarlo.
        aplicar(ctx, Accion::Limpiar, 0, pid);
        return;
    }
    let Some((uid, exe)) = identidad_de(pid) else {
        return;
    };
    let cortado = esta_cortado(&ctx.red, uid, &exe);
    aplicar(ctx, decidir(evento, cortado), uid, pid);

    // M2 — bloqueo por dominio: enrola/reconcilia los pids de un binario con regla
    // de dominio con las IPs que el snoop resolvió. Para un binario sin reglas y un
    // pid no enrolado no hace nada. Aditivo al kill-switch de M0 de arriba.
    super::dominio::reconciliar_pid(ctx, uid, pid, &exe, super::dominio::ahora_epoch());
}

/// Barre `/proc` y devuelve `pid → uid` de los procesos vivos cuyo ejecutable
/// está cortado para su uid. Es el **estado deseado** para
/// [`super::Enforcer::reconciliar`]: el barrido inicial al arrancar y la
/// resincronización cuando el usuario cambia el switch.
pub fn barrer_proc(red: &RedCortada) -> HashMap<u32, u32> {
    let mut deseados = HashMap::new();
    let Ok(entradas) = std::fs::read_dir("/proc") else {
        return deseados;
    };
    for entrada in entradas.flatten() {
        let Ok(nombre) = entrada.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = nombre.parse::<u32>() else {
            continue; // no es un pid: `/proc/self`, `/proc/stat`, …
        };
        if let Some((uid, exe)) = identidad_de(pid) {
            if esta_cortado(red, uid, &exe) {
                deseados.insert(pid, uid);
            }
        }
    }
    deseados
}

/// Barre `/proc` y reconcilia el enforcer contra lo que la política dice ahora.
/// Al arrancar (nada marcado → marca los vivos cortados) y al cambiar el switch
/// (marca lo que entró, limpia lo que salió). Pensada para correr fuera del
/// runtime async (en `spawn_blocking` o en el arranque).
pub fn resincronizar<M: MotorBpf>(ctx: &Contexto<M>) {
    let deseados = barrer_proc(&ctx.red);
    let Ok(mut guard) = ctx.enforcer.lock() else {
        return;
    };
    let Some(enf) = guard.as_mut() else {
        return;
    };
    for e in enf.reconciliar(&deseados) {
        tracing::error!("Cortafuegos (resincronización): {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La regla de enrolado por evento, que es el corazón de la sincronización.
    /// `exec` reevalúa en los dos sentidos (marca si está cortado, limpia si
    /// no); `fork` sólo marca (hereda), nunca limpia a un recién nacido; `exit`
    /// limpia siempre.
    #[test]
    fn la_regla_de_enrolado_por_evento() {
        assert_eq!(decidir(Evento::Exec, true), Accion::Bloquear);
        assert_eq!(decidir(Evento::Exec, false), Accion::Limpiar);
        assert_eq!(decidir(Evento::Fork, true), Accion::Bloquear);
        assert_eq!(decidir(Evento::Fork, false), Accion::Nada);
        assert_eq!(decidir(Evento::Exit, true), Accion::Limpiar);
        assert_eq!(decidir(Evento::Exit, false), Accion::Limpiar);
    }

    fn red_vacia() -> RedCortada {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn fijar_prende_y_apaga_el_corte_por_uid() {
        let red = red_vacia();
        assert!(!esta_cortado(&red, 1000, "/home/x/a"));

        fijar(&red, 1000, "/home/x/a", true);
        assert!(esta_cortado(&red, 1000, "/home/x/a"));
        // No contagia a otro uid ni a otro binario.
        assert!(!esta_cortado(&red, 1001, "/home/x/a"));
        assert!(!esta_cortado(&red, 1000, "/home/x/b"));

        fijar(&red, 1000, "/home/x/a", false);
        assert!(!esta_cortado(&red, 1000, "/home/x/a"));
        // Al quedar sin binarios, el uid sale del mapa (no deja una entrada vacía).
        assert!(red.lock().unwrap().get(&1000).is_none());
    }

    /// Apagar un corte que no estaba no rompe nada y no crea una entrada.
    #[test]
    fn apagar_lo_que_no_estaba_no_hace_nada() {
        let red = red_vacia();
        fijar(&red, 1000, "/home/x/a", false);
        assert!(red.lock().unwrap().is_empty());
    }

    // ── Adapters contra el `/proc` vivo del propio proceso de la prueba ────────

    fn mi_uid() -> u32 {
        // SAFETY: `getuid` no tiene precondiciones y no falla.
        unsafe { libc::getuid() }
    }

    fn mi_exe() -> String {
        let exe = std::fs::read_link("/proc/self/exe").expect("ejecutable propio");
        std::fs::canonicalize(&exe)
            .unwrap_or(exe)
            .to_string_lossy()
            .into_owned()
    }

    fn ctx_con_falso(red: RedCortada) -> Contexto<crate::firewall::MotorFalso> {
        Contexto {
            enforcer: Arc::new(Mutex::new(Some(crate::firewall::enforcer_falso()))),
            red,
            dominios: super::super::dominio::dominios_bloqueados_nuevo(HashMap::new()),
            dns: super::super::dns::modelo_dns_nuevo(),
        }
    }

    /// `barrer_proc` encuentra el proceso de la prueba si su ejecutable está
    /// cortado para su uid: ejercita la resolución de identidad y el recorrido de
    /// `/proc` sin root.
    #[test]
    fn barrer_proc_encuentra_el_proceso_propio_cortado() {
        let red = red_vacia();
        fijar(&red, mi_uid(), &mi_exe(), true);
        let deseados = barrer_proc(&red);
        assert_eq!(
            deseados.get(&std::process::id()),
            Some(&mi_uid()),
            "el proceso de la prueba tenía que aparecer como cortado"
        );
    }

    /// Y con el conjunto vacío, nadie aparece —ni el proceso propio—.
    #[test]
    fn barrer_proc_no_incluye_lo_no_cortado() {
        assert!(!barrer_proc(&red_vacia()).contains_key(&std::process::id()));
    }

    /// Un `exec` cortado marca el pid en el cortafuegos; el `exit` lo limpia. Es
    /// el camino entero —resolver identidad, decidir, aplicar— contra un
    /// cortafuegos de mentira.
    #[test]
    fn atender_un_exec_cortado_marca_el_pid_y_el_exit_lo_limpia() {
        let red = red_vacia();
        fijar(&red, mi_uid(), &mi_exe(), true);
        let ctx = ctx_con_falso(red);
        let pid = std::process::id();

        atender_evento(&ctx, Evento::Exec, pid);
        assert_eq!(
            ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados(),
            1,
            "el exec de un ejecutable cortado marca el pid"
        );

        atender_evento(&ctx, Evento::Exit, pid);
        assert_eq!(
            ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados(),
            0,
            "el exit limpia la marca"
        );
    }

    /// Un `exec` de un ejecutable **no** cortado no marca nada.
    #[test]
    fn atender_un_exec_no_cortado_no_marca() {
        let ctx = ctx_con_falso(red_vacia());
        atender_evento(&ctx, Evento::Exec, std::process::id());
        assert_eq!(ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados(), 0);
    }

    /// `resincronizar` marca los vivos cortados: barre `/proc`, encuentra el
    /// proceso propio y lo corta en el mapa del cortafuegos de mentira.
    #[test]
    fn resincronizar_marca_los_vivos_cortados() {
        let red = red_vacia();
        fijar(&red, mi_uid(), &mi_exe(), true);
        let ctx = ctx_con_falso(red);
        resincronizar(&ctx);

        let guard = ctx.enforcer.lock().unwrap();
        let enf = guard.as_ref().unwrap();
        assert!(
            enf.marcados() >= 1,
            "tenía que marcar al menos el proceso de la prueba"
        );
        assert!(
            !enf.motor().insertados.is_empty(),
            "y de verdad escribió el mapa del cortafuegos"
        );
    }

    /// Sin cortafuegos cargado (enforcer en `None`) los adapters recorren su
    /// camino pero no tocan nada: el daemon degrada sin romperse.
    #[test]
    fn sin_cortafuegos_los_adapters_no_rompen() {
        let red = red_vacia();
        fijar(&red, mi_uid(), &mi_exe(), true);
        let ctx: Contexto = Contexto {
            enforcer: Arc::new(Mutex::new(None)),
            red,
            dominios: super::super::dominio::dominios_bloqueados_nuevo(HashMap::new()),
            dns: super::super::dns::modelo_dns_nuevo(),
        };
        atender_evento(&ctx, Evento::Exec, std::process::id());
        atender_evento(&ctx, Evento::Exit, std::process::id());
        resincronizar(&ctx);
    }

    /// Un `fork` de un ejecutable cortado marca al hijo: hereda el corte del
    /// árbol sin esperar a un `exec`.
    #[test]
    fn un_fork_de_un_ejecutable_cortado_hereda_el_corte() {
        let red = red_vacia();
        fijar(&red, mi_uid(), &mi_exe(), true);
        let ctx = ctx_con_falso(red);
        atender_evento(&ctx, Evento::Fork, std::process::id());
        assert_eq!(ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados(), 1);
    }

    /// Un `fork` de un ejecutable que no está cortado no marca nada.
    #[test]
    fn un_fork_de_un_ejecutable_no_cortado_no_marca() {
        let ctx = ctx_con_falso(red_vacia());
        atender_evento(&ctx, Evento::Fork, std::process::id());
        assert_eq!(ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados(), 0);
    }

    /// Un `exec` a un ejecutable ya no cortado limpia la marca que el pid traía
    /// (el mismo número de pid que cambia de programa no arrastra el corte).
    #[test]
    fn un_exec_a_un_ejecutable_no_cortado_limpia_la_marca_vieja() {
        let red = red_vacia();
        fijar(&red, mi_uid(), &mi_exe(), true);
        let ctx = ctx_con_falso(red.clone());
        atender_evento(&ctx, Evento::Exec, std::process::id());
        assert_eq!(ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados(), 1);

        fijar(&red, mi_uid(), &mi_exe(), false);
        atender_evento(&ctx, Evento::Exec, std::process::id());
        assert_eq!(ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados(), 0);
    }

    /// Un `exit` de un pid que nunca se marcó no es error ni toca el mapa.
    #[test]
    fn un_exit_de_un_pid_no_marcado_no_toca_el_mapa() {
        let ctx = ctx_con_falso(red_vacia());
        atender_evento(&ctx, Evento::Exit, 4_000_000);
        let guard = ctx.enforcer.lock().unwrap();
        assert!(guard.as_ref().unwrap().motor().quitados.is_empty());
    }

    /// F3/F4: el uid de la clave sale del `/proc` del pid (real), no de la
    /// política: el corte guardado para otro uid no alcanza a este proceso, y el
    /// que sí le corresponde escribe la clave `(uid real << 32 | pid)`.
    #[test]
    fn el_uid_de_la_clave_sale_del_proceso_y_no_de_la_politica() {
        let ajeno = mi_uid().wrapping_add(1);
        let red = red_vacia();
        fijar(&red, ajeno, &mi_exe(), true);
        let ctx = ctx_con_falso(red);
        atender_evento(&ctx, Evento::Exec, std::process::id());
        assert_eq!(
            ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados(),
            0,
            "el corte de otro uid no puede alcanzar a este proceso"
        );
        assert!(!barrer_proc(&ctx.red).contains_key(&std::process::id()));

        fijar(&ctx.red, mi_uid(), &mi_exe(), true);
        atender_evento(&ctx, Evento::Exec, std::process::id());
        let guard = ctx.enforcer.lock().unwrap();
        let esperada = (u64::from(mi_uid()) << 32) | u64::from(std::process::id());
        assert_eq!(
            guard.as_ref().unwrap().motor().insertados,
            vec![(esperada, 1)]
        );
    }

    /// Fail-closed en el adapter: si el mapa está lleno el pid no figura como
    /// marcado (no se finge un corte que no está) y el evento no rompe nada.
    #[test]
    fn con_el_mapa_lleno_el_pid_no_figura_como_cortado() {
        let red = red_vacia();
        fijar(&red, mi_uid(), &mi_exe(), true);
        let motor = crate::firewall::MotorFalso {
            falla_al_insertar: Some(aya::maps::MapError::SyscallError(aya::sys::SyscallError {
                call: "bpf_map_update_elem",
                io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
            })),
            ..Default::default()
        };
        let enf = Enforcer::nuevo(crate::firewall::Firewall::con_motor(motor).unwrap());
        let ctx = Contexto {
            enforcer: Arc::new(Mutex::new(Some(enf))),
            red,
            dominios: super::super::dominio::dominios_bloqueados_nuevo(HashMap::new()),
            dns: super::super::dns::modelo_dns_nuevo(),
        };
        atender_evento(&ctx, Evento::Exec, std::process::id());
        assert_eq!(ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados(), 0);
    }

    /// Al apagar el switch, `resincronizar` limpia lo que quedó marcado.
    #[test]
    fn resincronizar_limpia_lo_que_dejo_de_estar_cortado() {
        let red = red_vacia();
        fijar(&red, mi_uid(), &mi_exe(), true);
        let ctx = ctx_con_falso(red.clone());
        resincronizar(&ctx);
        assert!(ctx.enforcer.lock().unwrap().as_ref().unwrap().marcados() >= 1);

        fijar(&red, mi_uid(), &mi_exe(), false);
        resincronizar(&ctx);
        let guard = ctx.enforcer.lock().unwrap();
        let enf = guard.as_ref().unwrap();
        assert_eq!(enf.marcados(), 0);
        let clave = (u64::from(mi_uid()) << 32) | u64::from(std::process::id());
        assert!(enf.motor().quitados.contains(&clave));
    }
}
