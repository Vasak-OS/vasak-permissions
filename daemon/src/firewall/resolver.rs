//! Forzar el resolvedor del sistema para las apps con regla por dominio (M2,
//! PR-C del #93). Cierra la evasión por DoH/DoT que PR-B dejó documentada.
//!
//! # Qué decide y dónde
//!
//! La **decisión** de cortar vive en el programa BPF (`fuerza_resolvedor`), que la
//! aplica en el camino del `connect()`; su espejo probable sin root es
//! [`corta_por_resolvedor`], la misma lógica como función pura (una prueba de
//! correspondencia ata la fuente BPF a esta decisión). Este módulo arma, en
//! userspace, los **datos** que esa decisión consulta:
//!
//! - `SYSTEM_RESOLVERS`: el stub de systemd-resolved (siempre) más los nameservers
//!   de `/etc/resolv.conf`. Un pid forzado sólo puede hablar DNS/DoT con estas IPs.
//! - `KNOWN_DOH`: una lista estática **mejor esfuerzo** de IPs de proveedores DoH
//!   conocidos. Un pid forzado no puede conectar a su 443.
//! - `FORCE_RESOLVER`: lo puebla la capa de enrolado por dominio (PR-B) reusando
//!   sus pids; acá sólo se fija el bit global `FORCE_DNS` según si se pudieron
//!   determinar los resolvedores.
//!
//! # Fail hacia no-romper
//!
//! El requisito duro: si NO se pueden determinar los resolvedores, **no** cortar
//! 53/853, para no tumbar todo el DNS de una app con regla. Por eso
//! [`resolvedores_desde`] devuelve `forzar_dns = false` cuando `resolv.conf` no se
//! pudo leer, y entonces los pids forzados quedan sólo con `FORCE_DOH`. El stub de
//! systemd-resolved se incluye **siempre**, así que el caso típico (systemd-resolved)
//! nunca se queda sin un resolvedor permitido.
//!
//! # Residual conocido
//!
//! Un DoH propio de la app a una IP **fuera** de `KNOWN_DOH` sigue evadiendo la
//! regla por dominio: el daemon no inspecciona TLS, sólo el destino. La lista es
//! mejor esfuerzo y actualizable; esto no es un cierre total, y así se documenta.

use std::collections::HashSet;

use super::dominio::ip_a_16;
use super::enrolar::Contexto;
use super::{MotorBpf, FORCE_DNS, FORCE_DOH};

/// Dónde están los resolvedores del sistema. Constante para que la prueba pueda
/// inyectar otra ruta sin toparse con el `/etc/resolv.conf` real del equipo.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// El stub local de systemd-resolved: `127.0.0.53` (resolución) y `127.0.0.54`
/// (reenvío). Se incluyen **siempre** en `SYSTEM_RESOLVERS`, porque en el caso
/// típico la app resuelve contra el stub y cortárselo rompería todo su DNS.
const STUB_SYSTEMD: [&str; 2] = ["127.0.0.53", "127.0.0.54"];

/// Las IPs de proveedores DoH conocidos. Lista estática **mejor esfuerzo**: cubre
/// a los grandes públicos, no es exhaustiva, y se actualiza agregando acá. Un DoH
/// propio a una IP que no esté en esta lista sigue evadiendo la regla por dominio.
const DOH_CONOCIDOS: [&str; 16] = [
    // Cloudflare (1.1.1.1)
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    // Google (8.8.8.8)
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    // Quad9 (9.9.9.9)
    "9.9.9.9",
    "149.112.112.112",
    "2620:fe::fe",
    "2620:fe::9",
    // AdGuard DNS
    "94.140.14.14",
    "94.140.15.15",
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
];

/// La decisión de corte del forzado del resolvedor, como función pura (M2, PR-C).
/// Es el **espejo** de `fuerza_resolvedor` del programa BPF: la fuente BPF resuelve
/// los dos booleanos contra los mapas y aplica exactamente esta lógica. Una prueba
/// de correspondencia ata los dos lados.
///
/// - 53/853 (DNS en claro y DoT): corta si `FORCE_DNS` está y el destino **no** es
///   un resolvedor del sistema —forzando la resolución por el resolvedor observable—.
/// - 443 (DoH): corta si `FORCE_DOH` está y el destino **sí** es una IP DoH conocida.
/// - cualquier otro puerto: no corta.
///
/// No la llama el daemon en producción (el corte real lo hace el programa BPF);
/// existe como **especificación probable sin root** de esa decisión, que la prueba
/// de correspondencia ata a la fuente BPF. De ahí el `allow(dead_code)`.
#[allow(dead_code)]
pub fn corta_por_resolvedor(
    flags: u8,
    puerto: u16,
    es_resolvedor_sistema: bool,
    es_doh_conocido: bool,
) -> bool {
    match puerto {
        53 | 853 => flags & FORCE_DNS != 0 && !es_resolvedor_sistema,
        443 => flags & FORCE_DOH != 0 && es_doh_conocido,
        _ => false,
    }
}

/// Las IPs DoH conocidas en 16 bytes, para poblar `KNOWN_DOH`. Las que no parseen
/// (no debería pasar: son literales) se descartan.
pub fn doh_conocidos() -> HashSet<[u8; 16]> {
    DOH_CONOCIDOS.iter().filter_map(|ip| ip_a_16(ip)).collect()
}

/// Parsea los nameservers de un `resolv.conf`: las líneas `nameserver <IP>`, sin
/// comentarios (`#`/`;`), con el id de zona de IPv6 link-local (`%eth0`) quitado.
/// Lo que no parsea como IP se descarta. Función pura, probada sin tocar el disco.
pub fn parse_nameservers(contenido: &str) -> HashSet<[u8; 16]> {
    let mut ips = HashSet::new();
    for linea in contenido.lines() {
        let linea = linea.trim();
        if linea.starts_with('#') || linea.starts_with(';') {
            continue;
        }
        let mut campos = linea.split_whitespace();
        if campos.next() != Some("nameserver") {
            continue;
        }
        let Some(crudo) = campos.next() else {
            continue;
        };
        // `fe80::1%eth0` → `fe80::1`: el id de zona no es parte de la IP.
        let sin_zona = crudo.split('%').next().unwrap_or(crudo);
        if let Some(bytes) = ip_a_16(sin_zona) {
            ips.insert(bytes);
        }
    }
    ips
}

/// El conjunto de `SYSTEM_RESOLVERS` y si se puede forzar 53/853, a partir del
/// contenido de `resolv.conf` (`None` = no se pudo leer).
///
/// - El stub de systemd-resolved va **siempre** (aunque `resolv.conf` falle).
/// - Los nameservers de `resolv.conf` se suman cuando se pudo leer.
/// - **Fail hacia no-romper:** `forzar_dns = false` si no se pudo leer `resolv.conf`
///   —entonces no se corta 53/853 para no tumbar el DNS de la app—; `true` si sí.
///
/// Función pura (contenido inyectado): se prueba sin tocar el disco.
pub fn resolvedores_desde(contenido: Option<&str>) -> (HashSet<[u8; 16]>, bool) {
    let mut ips: HashSet<[u8; 16]> = STUB_SYSTEMD.iter().filter_map(|ip| ip_a_16(ip)).collect();
    match contenido {
        Some(texto) => {
            ips.extend(parse_nameservers(texto));
            (ips, true)
        }
        // Sin poder leer `resolv.conf`: sólo el stub, y sin forzar 53/853.
        None => (ips, false),
    }
}

// ── Adapters: leen el disco y escriben los mapas a través del enforcer ─────────

/// Lee `resolv.conf` y arma el estado del forzado. `None` si no se pudo leer: el
/// llamador lo trata como «no se pudieron determinar los resolvedores». Bloqueante
/// a propósito (corre en `spawn_blocking`, como el barrido de `/proc`).
fn leer_estado() -> (HashSet<[u8; 16]>, bool) {
    let contenido = std::fs::read_to_string(RESOLV_CONF).ok();
    resolvedores_desde(contenido.as_deref())
}

/// Puebla `KNOWN_DOH` con la lista estática. Una vez al arrancar; la lista no
/// cambia en runtime. Degrada ruidoso si el cortafuegos no cargó o un write falla.
pub fn poblar_doh<M: MotorBpf>(ctx: &Contexto<M>) {
    let ips = doh_conocidos();
    let Ok(mut guard) = ctx.enforcer.lock() else {
        return;
    };
    let Some(enf) = guard.as_mut() else {
        return; // el cortafuegos no se cargó; ya se avisó al arrancar
    };
    for e in enf.poblar_doh(&ips) {
        tracing::error!("Cortafuegos (DoH conocido): {e}");
    }
}

/// Re-lee `resolv.conf` y lleva `SYSTEM_RESOLVERS` y el bit global `FORCE_DNS` al
/// día a través del enforcer. Lo corre el arranque y el barrido periódico, para
/// seguir los cambios de resolvedor sin reiniciar el daemon.
pub fn refrescar<M: MotorBpf>(ctx: &Contexto<M>) {
    let (resolvedores, forzar_dns) = leer_estado();
    if !forzar_dns {
        tracing::warn!(
            "Cortafuegos (forzar resolvedor): no se pudo determinar el resolvedor del \
             sistema ({RESOLV_CONF}); se deja pasar 53/853 para no cortar el DNS de las \
             apps con regla por dominio (fail hacia no-romper)"
        );
    }
    let Ok(mut guard) = ctx.enforcer.lock() else {
        return;
    };
    let Some(enf) = guard.as_mut() else {
        return;
    };
    for e in enf.actualizar_resolvedores(resolvedores, forzar_dns) {
        tracing::error!("Cortafuegos (forzar resolvedor): {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::enrolar::{Contexto, RedCortada};
    use crate::firewall::{enforcer_falso, MotorFalso};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn ip16(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut v = [0u8; 16];
        v[0] = a;
        v[1] = b;
        v[2] = c;
        v[3] = d;
        v
    }

    fn ctx_falso() -> Contexto<MotorFalso> {
        Contexto {
            enforcer: Arc::new(Mutex::new(Some(enforcer_falso()))),
            red: RedCortada::new(Mutex::new(HashMap::new())),
            dominios: crate::firewall::dominio::dominios_bloqueados_nuevo(HashMap::new()),
            dns: crate::firewall::dns::modelo_dns_nuevo(),
        }
    }

    // ── La decisión de corte, espejo del programa BPF ─────────────────────────

    /// 53 y 853: cortan sólo si `FORCE_DNS` está y el destino NO es resolvedor del
    /// sistema. Un resolvedor del sistema pasa; sin el bit, nada se corta.
    #[test]
    fn corta_el_dns_en_claro_y_dot_a_un_no_resolvedor() {
        for puerto in [53u16, 853] {
            // Forzado y no es resolvedor → corta.
            assert!(corta_por_resolvedor(FORCE_DNS, puerto, false, false));
            // Forzado pero ES resolvedor del sistema → pasa (no rompe el DNS).
            assert!(!corta_por_resolvedor(FORCE_DNS, puerto, true, false));
            // Sin el bit FORCE_DNS (fail hacia no-romper) → pasa aunque no sea resolvedor.
            assert!(!corta_por_resolvedor(FORCE_DOH, puerto, false, false));
        }
    }

    /// 443: corta sólo si `FORCE_DOH` está y el destino ES una IP DoH conocida.
    #[test]
    fn corta_el_doh_conocido_en_el_443() {
        assert!(corta_por_resolvedor(FORCE_DOH, 443, false, true));
        // DoH conocido pero sin el bit → no corta.
        assert!(!corta_por_resolvedor(FORCE_DNS, 443, false, true));
        // Con el bit pero la IP no es DoH conocido → no corta (residual documentado).
        assert!(!corta_por_resolvedor(FORCE_DOH, 443, false, false));
    }

    /// Cualquier otro puerto nunca se corta por el forzado del resolvedor, aunque
    /// los dos bits estén y la IP sea «conocida».
    #[test]
    fn otros_puertos_no_los_toca_el_forzado() {
        for puerto in [80u16, 443 - 1, 123, 443 + 1, 5353, 8853] {
            if puerto == 443 {
                continue;
            }
            assert!(!corta_por_resolvedor(
                FORCE_DNS | FORCE_DOH,
                puerto,
                false,
                true
            ));
        }
    }

    // ── Parseo de resolv.conf ─────────────────────────────────────────────────

    /// `parse_nameservers` toma las líneas `nameserver`, ignora comentarios y otras
    /// directivas, y le quita el id de zona a las IPv6 link-local.
    #[test]
    fn parse_nameservers_toma_solo_los_nameserver() {
        let conf = "\
# un comentario
; otro comentario
nameserver 127.0.0.53
nameserver 8.8.8.8
options edns0 trust-ad
search lan
nameserver fe80::1%eth0
nameserver no-es-ip
";
        let ips = parse_nameservers(conf);
        assert!(ips.contains(&ip16(127, 0, 0, 53)));
        assert!(ips.contains(&ip16(8, 8, 8, 8)));
        // La IPv6 link-local entra sin el id de zona.
        let mut fe80 = [0u8; 16];
        fe80[0] = 0xfe;
        fe80[1] = 0x80;
        fe80[15] = 1;
        assert!(ips.contains(&fe80));
        // «no-es-ip» se descartó; sólo quedaron las tres válidas.
        assert_eq!(ips.len(), 3);
    }

    /// Un `resolv.conf` sin ninguna línea `nameserver` da un conjunto vacío (de
    /// nameservers; el stub lo agrega `resolvedores_desde`).
    #[test]
    fn parse_nameservers_vacio_si_no_hay_ninguno() {
        assert!(parse_nameservers("search lan\noptions edns0\n").is_empty());
        assert!(parse_nameservers("").is_empty());
    }

    // ── Construcción del conjunto y fail hacia no-romper ──────────────────────

    /// Con `resolv.conf` legible: el stub SIEMPRE está, más los nameservers, y se
    /// fuerza 53/853 (`forzar_dns = true`).
    #[test]
    fn resolvedores_desde_incluye_el_stub_y_los_nameservers() {
        let (ips, forzar) = resolvedores_desde(Some("nameserver 192.168.1.1\n"));
        assert!(forzar, "con resolv.conf legible se fuerza 53/853");
        assert!(
            ips.contains(&ip16(127, 0, 0, 53)),
            "el stub 127.0.0.53 siempre"
        );
        assert!(
            ips.contains(&ip16(127, 0, 0, 54)),
            "el stub 127.0.0.54 siempre"
        );
        assert!(
            ips.contains(&ip16(192, 168, 1, 1)),
            "el nameserver del archivo"
        );
    }

    /// **Fail hacia no-romper:** sin poder leer `resolv.conf` (`None`), queda sólo
    /// el stub y `forzar_dns = false` —no se corta 53/853, para no tumbar el DNS—.
    #[test]
    fn resolvedores_desde_sin_resolv_conf_no_fuerza_pero_deja_el_stub() {
        let (ips, forzar) = resolvedores_desde(None);
        assert!(!forzar, "sin resolvedores determinados NO se fuerza 53/853");
        assert!(
            ips.contains(&ip16(127, 0, 0, 53)),
            "el stub igual queda permitido"
        );
        assert!(ips.contains(&ip16(127, 0, 0, 54)));
        assert_eq!(ips.len(), 2, "sólo el stub, nada más");
    }

    /// Un `resolv.conf` legible pero sin nameservers igual fuerza (el stub cubre el
    /// caso típico de systemd-resolved) y deja sólo el stub.
    #[test]
    fn resolv_conf_vacio_fuerza_con_solo_el_stub() {
        let (ips, forzar) = resolvedores_desde(Some("search lan\n"));
        assert!(forzar);
        assert_eq!(ips.len(), 2);
    }

    // ── La lista DoH ──────────────────────────────────────────────────────────

    /// La lista DoH incluye a los grandes públicos (Cloudflare, Google, Quad9) y
    /// todas sus entradas parsean a 16 bytes.
    #[test]
    fn doh_conocidos_incluye_los_grandes() {
        let doh = doh_conocidos();
        assert!(doh.contains(&ip16(1, 1, 1, 1)), "Cloudflare");
        assert!(doh.contains(&ip16(8, 8, 8, 8)), "Google");
        assert!(doh.contains(&ip16(9, 9, 9, 9)), "Quad9");
        // Todas las literales parsean: el conjunto tiene tantas como la lista.
        assert_eq!(doh.len(), DOH_CONOCIDOS.len());
    }

    // ── Adapters contra el cortafuegos de mentira ─────────────────────────────

    /// `poblar_doh` escribe toda la lista en `KNOWN_DOH` a través del enforcer.
    #[test]
    fn poblar_doh_escribe_la_lista() {
        let ctx = ctx_falso();
        poblar_doh(&ctx);
        let guard = ctx.enforcer.lock().unwrap();
        let motor = guard.as_ref().unwrap().motor();
        assert_eq!(motor.doh_insertados.len(), DOH_CONOCIDOS.len());
        assert!(motor.doh_insertados.contains(&ip16(1, 1, 1, 1)));
    }

    /// `actualizar_resolvedores` (vía el enforcer) escribe el stub y, al llamarse
    /// de nuevo con un nameserver más, agrega sólo la diferencia; al quitarlo, lo
    /// quita. El bit `forzar_dns` arranca en `false` y pasa a `true`.
    #[test]
    fn actualizar_resolvedores_diffea_el_conjunto() {
        let ctx = ctx_falso();
        // Primer refresco: sólo el stub, forzado true.
        {
            let (ips, forzar) = resolvedores_desde(Some("nameserver 192.0.2.1\n"));
            let mut g = ctx.enforcer.lock().unwrap();
            let errores = g.as_mut().unwrap().actualizar_resolvedores(ips, forzar);
            assert!(errores.is_empty());
        }
        {
            let g = ctx.enforcer.lock().unwrap();
            let m = g.as_ref().unwrap().motor();
            // Stub (x2) + el nameserver = 3 inserciones.
            assert_eq!(m.resolvedores_insertados.len(), 3);
            assert!(m.resolvedores_insertados.contains(&ip16(192, 0, 2, 1)));
        }
        // Segundo refresco con la IP cambiada: se agrega la nueva y se quita la vieja.
        {
            let (ips, forzar) = resolvedores_desde(Some("nameserver 192.0.2.2\n"));
            let mut g = ctx.enforcer.lock().unwrap();
            g.as_mut().unwrap().actualizar_resolvedores(ips, forzar);
            let m = g.as_ref().unwrap().motor();
            assert!(m.resolvedores_insertados.contains(&ip16(192, 0, 2, 2)));
            assert_eq!(m.resolvedores_quitados, vec![ip16(192, 0, 2, 1)]);
        }
    }

    /// Sin cortafuegos cargado (enforcer en `None`) los adapters no rompen nada.
    #[test]
    fn sin_cortafuegos_los_adapters_no_rompen() {
        let ctx: Contexto<MotorFalso> = Contexto {
            enforcer: Arc::new(Mutex::new(None)),
            red: RedCortada::new(Mutex::new(HashMap::new())),
            dominios: crate::firewall::dominio::dominios_bloqueados_nuevo(HashMap::new()),
            dns: crate::firewall::dns::modelo_dns_nuevo(),
        };
        poblar_doh(&ctx);
        refrescar(&ctx);
    }
}
