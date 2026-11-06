//! La capa de política del **bloqueo por dominio** (M2 del #93): decide qué IPs
//! cortarle a los pids de un binario con una regla de dominio, uniendo tres
//! fuentes y escribiendo el mapa BPF a través del [`super::Enforcer`].
//!
//! # Las tres fuentes y la función que las junta
//!
//! El estado del mapa `DOMAIN_BLOCKED` es una **función pura** de:
//!
//! - la **política**: `(uid, binary) → {dominios bloqueados}` ([`DominiosBloqueados`]);
//! - el **snoop de DNS** (PR-A): `(uid, IP) → dominio` con TTL ([`super::dns`]);
//! - los **pids vivos** del binario, que el conector de procesos enrola por
//!   exec/fork (reusando el enrolado por pid de M0).
//!
//! [`ips_deseadas`] junta la política y el snoop: las IPs que un `(uid, binary)`
//! tiene que cortar son las que el snoop vio resolver, no vencidas, para alguno de
//! los dominios que ese binario bloquea. El [`super::Enforcer`] reconcilia los pids
//! contra ese conjunto —agrega las que faltan, quita las que sobran—, así que una
//! regla nueva, una IP recién resuelta, un TTL vencido o una regla borrada son
//! todos el mismo `reconcile`.
//!
//! # Granularidad por binario, no por uid
//!
//! La regla es «a esta app, este dominio». Como casi todas las apps del escritorio
//! corren bajo el mismo uid, cortar por `(uid, IP)` bloquearía el dominio para
//! **todas**. Por eso el mapa BPF se clava por `(clave de pid, IP)` y acá sólo se
//! enrolan y reconcilian los pids del binario con la regla: otras apps del mismo
//! uid no tienen entradas y no se ven afectadas.
//!
//! # El daemon nunca resuelve: sólo observa
//!
//! Las IPs salen **siempre** del snoop —lo que el resolvedor del sistema ya
//! devolvió—, nunca de resolver el daemon (eso le daría salida de red a un servicio
//! root). La atribución del snoop es por uid, no por binario: si otra app del mismo
//! usuario resolvió el dominio, su IP también se le corta al binario con la regla
//! —correcto, la regla es sobre el dominio—. Una app que resuelve por su **propio
//! DoH/DoT** esconde el dominio del snoop y evade la regla; cerrar eso es PR-C
//! (forzar el resolvedor del sistema). Hasta entonces la regla por dominio es
//! evadible, y se documenta.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use super::dns::ModeloDnsCompartido;
use super::enrolar::Contexto;
use super::MotorBpf;

/// La política de bloqueo por dominio en memoria: `uid → binary → {dominios}`.
///
/// Es lo que las reglas de la política (persistidas) proyectan para consultarlas
/// sin leer el disco en el camino caliente. Lo arma el arranque
/// ([`crate::policy::PolicyStore::domain_rules_initial`]) y lo mantiene
/// `SetDomainRule`. Se comparte entre el conector de procesos, el snoop de DNS, el
/// barrido de TTL y el servicio.
pub type DominiosBloqueados = Arc<Mutex<HashMap<u32, HashMap<String, HashSet<String>>>>>;

/// Arma el modelo compartido desde el conjunto inicial de la política.
pub fn dominios_bloqueados_nuevo(
    inicial: HashMap<u32, HashMap<String, HashSet<String>>>,
) -> DominiosBloqueados {
    Arc::new(Mutex::new(inicial))
}

/// Los dominios que `(uid, binary)` tiene bloqueados ahora mismo. Clona y suelta
/// el candado: nunca se sostiene a través de otro candado.
pub fn dominios_de(dominios: &DominiosBloqueados, uid: u32, binary: &str) -> HashSet<String> {
    dominios
        .lock()
        .ok()
        .and_then(|m| m.get(&uid).and_then(|b| b.get(binary)).cloned())
        .unwrap_or_default()
}

/// Los ejecutables de `uid` que bloquean `domain` (comparando sin distinguir
/// mayúsculas, porque el DNS es insensible a la caja). Es lo que el snoop usa para
/// saber qué binarios reconciliar cuando ve resolver un dominio.
pub fn binarios_que_bloquean(dominios: &DominiosBloqueados, uid: u32, domain: &str) -> Vec<String> {
    let Ok(m) = dominios.lock() else {
        return Vec::new();
    };
    let Some(binarios) = m.get(&uid) else {
        return Vec::new();
    };
    binarios
        .iter()
        .filter(|(_, doms)| doms.iter().any(|d| d.eq_ignore_ascii_case(domain)))
        .map(|(binary, _)| binary.clone())
        .collect()
}

/// Prende o apaga una regla de dominio en el modelo compartido. Lo llama
/// `SetDomainRule` tras guardar la política, para que los `exec` y las respuestas
/// de DNS futuras ya vean el cambio sin releer el disco. Poda las entradas vacías.
pub fn fijar(dominios: &DominiosBloqueados, uid: u32, binary: &str, domain: &str, bloqueado: bool) {
    let Ok(mut m) = dominios.lock() else { return };
    if bloqueado {
        m.entry(uid)
            .or_default()
            .entry(binary.to_string())
            .or_default()
            .insert(domain.to_string());
    } else if let Some(binarios) = m.get_mut(&uid) {
        if let Some(doms) = binarios.get_mut(binary) {
            doms.remove(domain);
            if doms.is_empty() {
                binarios.remove(binary);
            }
        }
        if binarios.is_empty() {
            m.remove(&uid);
        }
    }
}

/// Una IP en texto a los 16 bytes del mapa BPF: IPv4 en los primeros 4 bytes, cero
/// el resto; los 16 de IPv6. **Tiene que coincidir** con el formato de
/// `ConnectionEvent.dst` que arma el programa BPF, o la clave de dominio no
/// emparejaría con el destino del `connect()`. `None` si no parsea como IP.
pub fn ip_a_16(ip: &str) -> Option<[u8; 16]> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&v4.octets());
            Some(b)
        }
        IpAddr::V6(v6) => Some(v6.octets()),
    }
}

/// Las IPs que `(uid, binary)` tiene que cortar: la unión, sobre los dominios que
/// bloquea, de las IPs que el snoop vio resolver y todavía no vencieron. Es el
/// **estado deseado** que el [`super::Enforcer`] reconcilia contra el mapa.
///
/// Función pura (con `ahora` inyectado): se prueba sin root ni red. Toma el candado
/// de la política y el del snoop por separado y los suelta antes de que el
/// enforcer tome el suyo, así que no hay orden de candados que pueda trabarse.
pub fn ips_deseadas(
    dominios: &DominiosBloqueados,
    dns: &ModeloDnsCompartido,
    uid: u32,
    binary: &str,
    ahora: u64,
) -> HashSet<[u8; 16]> {
    let domains = dominios_de(dominios, uid, binary);
    if domains.is_empty() {
        return HashSet::new();
    }
    let mut ips = HashSet::new();
    if let Ok(d) = dns.lock() {
        for dom in &domains {
            for ip in d.ips_de(uid, dom, ahora) {
                if let Some(bytes) = ip_a_16(&ip) {
                    ips.insert(bytes);
                }
            }
        }
    }
    ips
}

/// Segundos desde el epoch, para el TTL del snoop.
pub fn ahora_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Adapters: juntan las fuentes y escriben el mapa a través del enforcer ──────

/// Reconcilia el bloqueo por dominio de **un** pid: calcula sus IPs deseadas y las
/// lleva al mapa. Lo llama el conector de procesos en cada exec/fork, y el barrido
/// de reglas. Si el binario no tiene reglas y el pid no estaba enrolado, no hace
/// nada (el caso de la enorme mayoría de los procesos).
pub fn reconciliar_pid<M: MotorBpf>(
    ctx: &Contexto<M>,
    uid: u32,
    pid: u32,
    binary: &str,
    ahora: u64,
) {
    let tiene_reglas = !dominios_de(&ctx.dominios, uid, binary).is_empty();
    let deseadas = ips_deseadas(&ctx.dominios, &ctx.dns, uid, binary, ahora);
    let Ok(mut guard) = ctx.enforcer.lock() else {
        return;
    };
    let Some(enf) = guard.as_mut() else {
        return; // el cortafuegos no se cargó; ya se avisó al arrancar
    };
    for e in enf.reconciliar_dominio_pid(uid, pid, binary, deseadas, tiene_reglas) {
        tracing::error!("Cortafuegos (dominio): {e}");
    }
}

/// Reconcilia los pids vivos de cada binario de `uid` que bloquea `domain`. Lo
/// llama el snoop de DNS al ver resolver un dominio: las IPs recién resueltas
/// entran al corte de los pids de ese binario.
pub fn reconciliar_dominio<M: MotorBpf>(ctx: &Contexto<M>, uid: u32, domain: &str, ahora: u64) {
    for binary in binarios_que_bloquean(&ctx.dominios, uid, domain) {
        // El binario está en `binarios_que_bloquean`, así que tiene reglas.
        let deseadas = ips_deseadas(&ctx.dominios, &ctx.dns, uid, &binary, ahora);
        let Ok(mut guard) = ctx.enforcer.lock() else {
            return;
        };
        let Some(enf) = guard.as_mut() else {
            return;
        };
        for e in enf.reconciliar_dominio_binario(uid, &binary, deseadas, true) {
            tracing::error!("Cortafuegos (dominio): {e}");
        }
    }
}

/// Barrido periódico de TTL: recalcula las IPs deseadas de cada `(uid, binary)` con
/// pids enrolados y las reconcilia, bajando las que vencieron. Sin esto, una IP que
/// dejó de resolver el dominio seguiría cortada hasta el próximo evento del binario
/// —y si la IP se reasignó a otro dominio, se cortaría de más—.
pub fn barrer<M: MotorBpf>(ctx: &Contexto<M>, ahora: u64) {
    let pares = {
        let Ok(guard) = ctx.enforcer.lock() else {
            return;
        };
        let Some(enf) = guard.as_ref() else {
            return;
        };
        enf.pares_dominio()
    };
    for (uid, binary) in pares {
        let tiene_reglas = !dominios_de(&ctx.dominios, uid, &binary).is_empty();
        let deseadas = ips_deseadas(&ctx.dominios, &ctx.dns, uid, &binary, ahora);
        let Ok(mut guard) = ctx.enforcer.lock() else {
            return;
        };
        let Some(enf) = guard.as_mut() else {
            return;
        };
        for e in enf.reconciliar_dominio_binario(uid, &binary, deseadas, tiene_reglas) {
            tracing::error!("Cortafuegos (dominio, barrido): {e}");
        }
    }
}

/// Barre `/proc` y reconcilia el bloqueo por dominio de cada proceso vivo. Lo corre
/// `SetDomainRule` tras cambiar una regla: enrola los pids del binario que ahora la
/// tiene y limpia los que la perdieron, para que la regla tenga efecto sin reiniciar
/// la app. En `spawn_blocking`, como el barrido de M0.
pub fn resincronizar<M: MotorBpf>(ctx: &Contexto<M>, ahora: u64) {
    let Ok(entradas) = std::fs::read_dir("/proc") else {
        return;
    };
    for entrada in entradas.flatten() {
        let Ok(nombre) = entrada.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = nombre.parse::<u32>() else {
            continue; // no es un pid: `/proc/self`, `/proc/stat`, …
        };
        if let Some((uid, exe)) = super::enrolar::identidad_de(pid) {
            reconciliar_pid(ctx, uid, pid, &exe, ahora);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::dns::{modelo_dns_nuevo, RegistroDns, RespuestaDns};
    use crate::firewall::enrolar::RedCortada;
    use crate::firewall::{enforcer_falso, Enforcer, MotorFalso};

    fn dominios_vacios() -> DominiosBloqueados {
        dominios_bloqueados_nuevo(HashMap::new())
    }

    fn ip16(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut v = [0u8; 16];
        v[0] = a;
        v[1] = b;
        v[2] = c;
        v[3] = d;
        v
    }

    fn resp(dominio: &str, ips: &[&str], ttl: u32) -> RespuestaDns {
        RespuestaDns {
            dominio: dominio.into(),
            registros: ips
                .iter()
                .map(|ip| RegistroDns {
                    ip: (*ip).into(),
                    ttl,
                })
                .collect(),
        }
    }

    fn ctx_falso(dominios: DominiosBloqueados, dns: ModeloDnsCompartido) -> Contexto<MotorFalso> {
        Contexto {
            enforcer: Arc::new(Mutex::new(Some(enforcer_falso()))),
            red: RedCortada::new(Mutex::new(HashMap::new())),
            dominios,
            dns,
        }
    }

    /// `ip_a_16` deja la IPv4 en los primeros 4 bytes (como el programa BPF) y la
    /// IPv6 completa; lo que no es una IP da `None`.
    #[test]
    fn ip_a_16_respeta_el_formato_del_programa_bpf() {
        assert_eq!(ip_a_16("192.0.2.1"), Some(ip16(192, 0, 2, 1)));
        assert_eq!(
            ip_a_16("2001:db8::1"),
            Some([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(ip_a_16("no-es-ip"), None);
        assert_eq!(ip_a_16(""), None);
    }

    /// `fijar` prende y apaga una regla por `(uid, binary, domain)` sin contagiar a
    /// otro uid, binario ni dominio, y poda las entradas vacías.
    #[test]
    fn fijar_prende_y_apaga_sin_contagiar() {
        let dom = dominios_vacios();
        assert!(dominios_de(&dom, 1000, "/app").is_empty());

        fijar(&dom, 1000, "/app", "ads.com", true);
        fijar(&dom, 1000, "/app", "track.io", true);
        assert_eq!(
            dominios_de(&dom, 1000, "/app"),
            ["ads.com".to_string(), "track.io".to_string()].into()
        );
        // No contagia.
        assert!(dominios_de(&dom, 1001, "/app").is_empty());
        assert!(dominios_de(&dom, 1000, "/otro").is_empty());

        fijar(&dom, 1000, "/app", "ads.com", false);
        assert_eq!(
            dominios_de(&dom, 1000, "/app"),
            ["track.io".to_string()].into()
        );
        fijar(&dom, 1000, "/app", "track.io", false);
        assert!(dominios_de(&dom, 1000, "/app").is_empty());
        // Al quedar vacío, el uid sale del mapa (no deja una entrada vacía).
        assert!(dom.lock().unwrap().get(&1000).is_none());
    }

    /// `binarios_que_bloquean` encuentra los binarios de un uid que cortan un
    /// dominio, sin distinguir mayúsculas (el DNS es insensible a la caja).
    #[test]
    fn binarios_que_bloquean_empareja_sin_caja() {
        let dom = dominios_vacios();
        fijar(&dom, 1000, "/mail", "ads.com", true);
        fijar(&dom, 1000, "/browser", "ads.com", true);
        fijar(&dom, 1000, "/mail", "otro.com", true);

        let mut b = binarios_que_bloquean(&dom, 1000, "ADS.COM");
        b.sort();
        assert_eq!(b, vec!["/browser".to_string(), "/mail".to_string()]);
        assert!(binarios_que_bloquean(&dom, 1000, "nadie.com").is_empty());
        assert!(binarios_que_bloquean(&dom, 1001, "ads.com").is_empty());
    }

    /// `ips_deseadas` une los dominios del binario con lo que el snoop resolvió, no
    /// vencido, y lo convierte a los 16 bytes del mapa. Sin reglas, vacío.
    #[test]
    fn ips_deseadas_une_la_politica_y_el_snoop() {
        let dom = dominios_vacios();
        let dns = modelo_dns_nuevo();
        // Sin reglas: no hay nada deseado aunque el snoop tenga entradas.
        dns.lock()
            .unwrap()
            .observar(1000, &resp("ads.com", &["192.0.2.1"], 300), 100);
        assert!(ips_deseadas(&dom, &dns, 1000, "/app", 150).is_empty());

        // Con la regla, la IP resuelta entra.
        fijar(&dom, 1000, "/app", "ads.com", true);
        assert_eq!(
            ips_deseadas(&dom, &dns, 1000, "/app", 150),
            [ip16(192, 0, 2, 1)].into()
        );

        // Una entrada vencida no cuenta (TTL 300, observada en 100 → vence 400).
        assert!(ips_deseadas(&dom, &dns, 1000, "/app", 500).is_empty());

        // La IP de otro uid no se mezcla.
        assert!(ips_deseadas(&dom, &dns, 1001, "/app", 150).is_empty());
    }

    /// Varios dominios de un binario se unen; las IPs de los dos entran.
    #[test]
    fn ips_deseadas_une_varios_dominios() {
        let dom = dominios_vacios();
        let dns = modelo_dns_nuevo();
        fijar(&dom, 1000, "/app", "a.com", true);
        fijar(&dom, 1000, "/app", "b.com", true);
        dns.lock()
            .unwrap()
            .observar(1000, &resp("a.com", &["192.0.2.1"], 300), 100);
        dns.lock()
            .unwrap()
            .observar(1000, &resp("b.com", &["192.0.2.2", "192.0.2.3"], 300), 100);
        assert_eq!(
            ips_deseadas(&dom, &dns, 1000, "/app", 150),
            [ip16(192, 0, 2, 1), ip16(192, 0, 2, 2), ip16(192, 0, 2, 3)].into()
        );
    }

    /// El adapter `reconciliar_pid` enrola un pid de un binario con regla con las
    /// IPs resueltas, y limpia cuando la regla desaparece.
    #[test]
    fn reconciliar_pid_enrola_y_limpia_segun_la_regla() {
        let dom = dominios_vacios();
        let dns = modelo_dns_nuevo();
        fijar(&dom, 1000, "/app", "ads.com", true);
        dns.lock()
            .unwrap()
            .observar(1000, &resp("ads.com", &["192.0.2.1"], 300), 100);
        let ctx = ctx_falso(dom.clone(), dns);

        reconciliar_pid(&ctx, 1000, 42, "/app", 150);
        assert_eq!(
            ctx.enforcer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ips_dominio(42),
            Some(vec![ip16(192, 0, 2, 1)])
        );

        // Se borra la regla: el próximo reconcile limpia el pid.
        fijar(&dom, 1000, "/app", "ads.com", false);
        reconciliar_pid(&ctx, 1000, 42, "/app", 150);
        assert_eq!(
            ctx.enforcer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .dominio_marcados(),
            0
        );
    }

    /// Un pid de un binario **sin** regla no se enrola: la granularidad es por
    /// binario, no por uid —otra app del mismo usuario no se corta—.
    #[test]
    fn reconciliar_pid_de_un_binario_sin_regla_no_corta() {
        let dom = dominios_vacios();
        let dns = modelo_dns_nuevo();
        // /app tiene regla; /otro no, bajo el mismo uid.
        fijar(&dom, 1000, "/app", "ads.com", true);
        dns.lock()
            .unwrap()
            .observar(1000, &resp("ads.com", &["192.0.2.1"], 300), 100);
        let ctx = ctx_falso(dom, dns);

        reconciliar_pid(&ctx, 1000, 99, "/otro", 150);
        assert_eq!(
            ctx.enforcer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .dominio_marcados(),
            0,
            "una app sin regla del mismo uid no se corta"
        );
    }

    /// `reconciliar_dominio` (la rama del snoop) lleva la IP recién resuelta a los
    /// pids ya enrolados del binario que bloquea ese dominio.
    #[test]
    fn reconciliar_dominio_empuja_la_ip_a_los_pids_del_binario() {
        let dom = dominios_vacios();
        let dns = modelo_dns_nuevo();
        fijar(&dom, 1000, "/app", "ads.com", true);
        let ctx = ctx_falso(dom, dns.clone());

        // El pid queda enrolado aunque todavía no haya IPs: así el empujón del
        // snoop lo alcanza. Con reglas pero sin resolver, su conjunto está vacío.
        reconciliar_pid(&ctx, 1000, 42, "/app", 100);
        assert_eq!(
            ctx.enforcer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ips_dominio(42),
            Some(vec![]),
            "un binario con regla enrola el pid aunque no haya IPs todavía"
        );

        // Ahora el snoop ve resolver ads.com: la IP entra al corte del pid.
        dns.lock()
            .unwrap()
            .observar(1000, &resp("ads.com", &["192.0.2.1"], 300), 200);
        reconciliar_dominio(&ctx, 1000, "ads.com", 250);
        assert_eq!(
            ctx.enforcer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ips_dominio(42),
            Some(vec![ip16(192, 0, 2, 1)])
        );
    }

    /// El barrido de TTL baja la IP cuyo snoop venció: el pid sigue enrolado pero su
    /// corte se recalcula a vacío.
    #[test]
    fn barrer_baja_las_ips_vencidas() {
        let dom = dominios_vacios();
        let dns = modelo_dns_nuevo();
        fijar(&dom, 1000, "/app", "ads.com", true);
        dns.lock()
            .unwrap()
            .observar(1000, &resp("ads.com", &["192.0.2.1"], 300), 100);
        let ctx = ctx_falso(dom, dns);

        reconciliar_pid(&ctx, 1000, 42, "/app", 150);
        assert_eq!(
            ctx.enforcer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ips_dominio(42),
            Some(vec![ip16(192, 0, 2, 1)])
        );

        // Mucho después de vencer (300 + 100 = 400): el barrido la baja. El pid
        // sigue enrolado (la regla sigue), pero sin IPs cortadas.
        barrer(&ctx, 100_000);
        assert_eq!(
            ctx.enforcer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ips_dominio(42),
            Some(vec![]),
            "la IP vencida se bajó del mapa"
        );
    }

    /// Sin cortafuegos cargado (enforcer en `None`) los adapters recorren su camino
    /// sin romperse: el daemon degrada sin tumbar nada.
    #[test]
    fn sin_cortafuegos_los_adapters_no_rompen() {
        let dom = dominios_vacios();
        let dns = modelo_dns_nuevo();
        fijar(&dom, 1000, "/app", "ads.com", true);
        let ctx: Contexto<MotorFalso> = Contexto {
            enforcer: Arc::new(Mutex::new(None)),
            red: RedCortada::new(Mutex::new(HashMap::new())),
            dominios: dom,
            dns,
        };
        reconciliar_pid(&ctx, 1000, 42, "/app", 1);
        reconciliar_dominio(&ctx, 1000, "ads.com", 1);
        barrer(&ctx, 1);
    }

    /// Un `Enforcer` directo sobre el falso deja leer lo que se escribió, para las
    /// pruebas que no pasan por el adapter (sanidad del helper).
    #[test]
    fn el_enforcer_falso_arranca_sin_dominios() {
        let e: Enforcer<MotorFalso> = enforcer_falso();
        assert_eq!(e.dominio_marcados(), 0);
    }
}
