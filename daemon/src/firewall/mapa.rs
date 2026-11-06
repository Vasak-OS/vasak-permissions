//! El lector del ring buffer del cortafuegos: el adapter privilegiado del mapa en
//! vivo (M1 del #93).
//!
//! # Qué hace y por qué no se cubre
//!
//! Lee los eventos que el programa BPF emite por `EVENTS`, los parsea (lógica pura
//! en [`super::conexiones`], probada sin root), los enriquece con el ejecutable
//! del pid (la caché del conector o `/proc`), los vuelca al modelo compartido y
//! emite la señal `ConnectionObserved` cuando el destino es nuevo.
//!
//! Necesita root/`CAP_BPF` para leer el ring buffer, así que —como `escuchar` en
//! `procesos.rs`— es un adapter fino, sin lógica propia que probar: la lógica
//! parseable vive en [`super::conexiones`]. El CI no lo corre; lo ejercita la
//! prueba de integración como root y el uso real.
//!
//! # Degrada ruidoso
//!
//! Si no se puede envolver el descriptor o la lectura se cae, se registra y se
//! sale: el enforcement de M0 sigue (es otro camino), sólo se pierde el mapa en
//! vivo.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aya::maps::{MapData, RingBuf};
use tokio::io::unix::AsyncFd;
use zbus::object_server::SignalEmitter;
use zbus::Connection;

use vasak_permissions_protocol::{SERVICE_INTERFACE, SERVICE_PATH};

use super::conexiones::{parsear, ModeloCompartido};
use super::dns::ModeloDnsCompartido;
use crate::procesos::Cache;

/// El nombre del ring buffer en el objeto BPF (el del `static` en
/// `firewall-ebpf`). Si se renombra allá y no acá, tomarlo falla en vez de leer en
/// silencio un mapa que no existe.
pub const MAPA_EVENTOS: &str = "EVENTS";

/// Lee el ring buffer para siempre, enriqueciendo y volcando al modelo. Se lanza
/// como task de tokio junto con la carga del cortafuegos.
pub async fn escuchar(
    ring: RingBuf<MapData>,
    connection: Connection,
    modelo: ModeloCompartido,
    procesos: Cache,
    dns: ModeloDnsCompartido,
) {
    // `AsyncFd::new` quedó deprecada en tokio por seguridad de E/S, pero su
    // reemplazo (`AsyncFd::register`) no existe en la versión fijada en
    // `Cargo.lock` (1.53.3): todos sus constructores están deprecados ahí sin uno
    // nuevo. `RingBuf` es dueño de su descriptor mientras viva este task, así que
    // el uso es sólido. Cambiar a `register` cuando el tokio base lo traiga.
    #[allow(deprecated)]
    let mut fd = match AsyncFd::new(ring) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::error!(
                "No se pudo vigilar el ring buffer del cortafuegos ({e}); \
                 el mapa de conexiones en vivo no va a actualizarse"
            );
            return;
        }
    };

    tracing::info!("Leyendo el mapa de conexiones en vivo del cortafuegos");
    loop {
        let mut guard = match fd.readable_mut().await {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("El ring buffer del cortafuegos se cerró ({e}); se deja de leer");
                return;
            }
        };

        // Los uid con un destino nuevo en esta tanda: se avisa una vez por uid al
        // final, no por cada evento. Vaciar el ring sin sostener nada async.
        let mut con_novedad: Vec<u32> = Vec::new();
        {
            let ring = guard.get_inner_mut();
            while let Some(evento) = ring.next() {
                if let Some(uid) = procesar_evento(&evento, &modelo, &procesos, &dns, ahora_epoch())
                {
                    if !con_novedad.contains(&uid) {
                        con_novedad.push(uid);
                    }
                }
            }
        }
        guard.clear_ready();

        for uid in con_novedad {
            avisar(&connection, uid).await;
        }
    }
}

/// El corazón del lector, separado de la E/S para poder probarlo sin root ni ring
/// buffer: parsea el evento crudo, resuelve el ejecutable del pid, lo enriquece con
/// el dominio del snoop de DNS y lo vuelca al modelo. Devuelve el uid **si el
/// destino era nuevo** —cuando corresponde avisar— y `None` si no se pudo parsear o
/// ya se había visto.
fn procesar_evento(
    bytes: &[u8],
    modelo: &ModeloCompartido,
    procesos: &Cache,
    dns: &ModeloDnsCompartido,
    ahora: u64,
) -> Option<u32> {
    let ev = parsear(bytes)?;
    let exe = resolver_exe(procesos, ev.tgid);
    // El dominio que esta app ató a esta IP, si el snoop lo vio y no venció. `None`
    // ante cualquier contratiempo (candado envenenado, sin entrada): la fila se
    // muestra por IP, como en M1.
    let dominio = dns
        .lock()
        .ok()
        .and_then(|d| d.dominio_de(ev.uid, &ev.ip, ahora));
    let nuevo = modelo
        .lock()
        .map(|mut m| m.observar(exe, &ev, dominio, ahora))
        .unwrap_or(false);
    nuevo.then_some(ev.uid)
}

/// El ejecutable del pid, para la fila del mapa. Primero la caché del conector
/// —la ruta que tenía al hacer `exec`—; si no está (un proceso de sistema, o uno
/// que la caché no guarda), se lee `/proc/<pid>/exe` en vivo, que suele existir
/// porque la conexión recién ocurrió. Si tampoco, se nombra por el pid: una fila
/// sin nombre es peor que una con el número.
fn resolver_exe(cache: &Cache, pid: u32) -> String {
    if let Some(ruta) = crate::procesos::recordada(cache, pid, ahora_dur()) {
        return ruta.to_string_lossy().into_owned();
    }
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| {
            std::fs::canonicalize(&p)
                .unwrap_or(p)
                .to_string_lossy()
                .into_owned()
        })
        .unwrap_or_else(|_| format!("pid {pid}"))
}

/// Emite la señal `ConnectionObserved` para un uid. Lleva **sólo** el uid —no el
/// destino—: la señal va al bus del sistema, que la entrega a cualquiera, así que
/// no puede cargar los destinos de una persona. Es un aviso de «refrescá»; el
/// cliente llama a `ListConnections`, que filtra por su uid y sólo le da lo suyo.
async fn avisar(connection: &Connection, uid: u32) {
    let emisor = match SignalEmitter::new(connection, SERVICE_PATH) {
        Ok(emisor) => emisor,
        Err(e) => {
            tracing::debug!("No se pudo armar el emisor de la señal de conexión: {e}");
            return;
        }
    };
    if let Err(e) = crate::PermissionService::connection_observed(&emisor, uid).await {
        tracing::debug!("No se pudo emitir ConnectionObserved ({SERVICE_INTERFACE}): {e}");
    }
}

fn ahora_dur() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

fn ahora_epoch() -> u64 {
    ahora_dur().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::conexiones::modelo_nuevo;
    use crate::firewall::dns::{modelo_dns_nuevo, parsear_respuesta};
    use crate::procesos::cache_nueva;

    /// El uid del proceso de la prueba, para fabricar un evento a su nombre.
    fn mi_uid() -> u32 {
        // SAFETY: `getuid` no tiene precondiciones y no falla.
        unsafe { libc::getuid() }
    }

    /// Arma los 32 bytes de un `ConnectionEvent`, como el programa BPF, para
    /// ejercitar el lector sin cargar BPF ni leer un ring buffer.
    fn bytes_evento(uid: u32, tgid: u32) -> Vec<u8> {
        let mut m = Vec::with_capacity(32);
        m.extend_from_slice(&uid.to_le_bytes());
        m.extend_from_slice(&tgid.to_le_bytes());
        m.extend_from_slice(&[192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // dst
        m.extend_from_slice(&443u16.to_le_bytes()); // port
        m.push(2); // AF_INET
        m.push(6); // IPPROTO_TCP
        m.push(0); // permitido
        m.extend_from_slice(&[0u8; 3]); // relleno
        m
    }

    /// `procesar_evento` vuelca el evento al modelo y devuelve el uid la primera
    /// vez (hay que avisar), `None` la segunda (ya se vio). Es el camino del lector
    /// sin la E/S del ring buffer.
    #[test]
    fn procesar_un_evento_lo_vuelca_y_avisa_solo_la_primera_vez() {
        let modelo = modelo_nuevo();
        let cache = cache_nueva();
        let dns = modelo_dns_nuevo();
        let bytes = bytes_evento(mi_uid(), std::process::id());

        assert_eq!(
            procesar_evento(&bytes, &modelo, &cache, &dns, 100),
            Some(mi_uid()),
            "la primera vez devuelve el uid para avisar"
        );
        assert_eq!(
            procesar_evento(&bytes, &modelo, &cache, &dns, 101),
            None,
            "la repetición no vuelve a avisar"
        );

        // Y quedó en el modelo, con el ejecutable del proceso resuelto. Sin una
        // entrada DNS, la fila no tiene dominio (se mostraría por IP).
        let foto = modelo.lock().unwrap().instantanea(mi_uid());
        assert_eq!(foto.len(), 1);
        assert_eq!(foto[0].ip, "192.0.2.1");
        assert_eq!(foto[0].count, 2);
        assert!(foto[0].allowed);
        assert!(!foto[0].binary_path.is_empty());
        assert_eq!(foto[0].domain, None);
    }

    /// Cuando el snoop ató la IP de destino a un dominio para ese uid, la conexión
    /// observada lo muestra: es el enriquecimiento del mapa con el dominio (M2).
    #[test]
    fn el_evento_se_enriquece_con_el_dominio_del_snoop() {
        let modelo = modelo_nuevo();
        let cache = cache_nueva();
        let dns = modelo_dns_nuevo();
        // El snoop vio una respuesta que ató 192.0.2.1 → example.com para este uid.
        let respuesta = parsear_respuesta(&respuesta_dns(&["example", "com"], [192, 0, 2, 1]))
            .expect("respuesta válida");
        dns.lock().unwrap().observar(mi_uid(), &respuesta, 100);

        let bytes = bytes_evento(mi_uid(), std::process::id());
        procesar_evento(&bytes, &modelo, &cache, &dns, 150);

        let foto = modelo.lock().unwrap().instantanea(mi_uid());
        assert_eq!(foto.len(), 1);
        assert_eq!(foto[0].ip, "192.0.2.1");
        assert_eq!(
            foto[0].domain.as_deref(),
            Some("example.com"),
            "la IP de destino casó con el dominio resuelto"
        );

        // Otro uid con el mismo destino no hereda el dominio: la atribución es por
        // (uid, IP).
        let ajeno = mi_uid().wrapping_add(1);
        procesar_evento(
            &bytes_evento(ajeno, std::process::id()),
            &modelo,
            &cache,
            &dns,
            160,
        );
        let suya = modelo.lock().unwrap().instantanea(ajeno);
        assert_eq!(suya[0].domain, None, "el dominio no cruza de un uid a otro");
    }

    /// Una entrada DNS vencida no enriquece: la fila se muestra por IP. Protege la
    /// garantía TTL del snoop en el camino del mapa.
    #[test]
    fn una_entrada_dns_vencida_no_enriquece() {
        let modelo = modelo_nuevo();
        let cache = cache_nueva();
        let dns = modelo_dns_nuevo();
        let respuesta = parsear_respuesta(&respuesta_dns(&["corto", "com"], [192, 0, 2, 1]))
            .expect("respuesta válida");
        // TTL 300, observada en t=100: vence en 400.
        dns.lock().unwrap().observar(mi_uid(), &respuesta, 100);

        let bytes = bytes_evento(mi_uid(), std::process::id());
        procesar_evento(&bytes, &modelo, &cache, &dns, 100_000); // mucho después
        assert_eq!(modelo.lock().unwrap().instantanea(mi_uid())[0].domain, None);
    }

    /// Una conexión cuya IP no casa con ninguna entrada del snoop (aunque el uid
    /// tenga otras) queda por IP, sin dominio.
    #[test]
    fn una_ip_sin_entrada_del_snoop_queda_por_ip() {
        let modelo = modelo_nuevo();
        let cache = cache_nueva();
        let dns = modelo_dns_nuevo();
        let respuesta = parsear_respuesta(&respuesta_dns(&["otro", "com"], [192, 0, 2, 99]))
            .expect("respuesta válida");
        dns.lock().unwrap().observar(mi_uid(), &respuesta, 100);

        procesar_evento(
            &bytes_evento(mi_uid(), std::process::id()),
            &modelo,
            &cache,
            &dns,
            150,
        );
        let foto = modelo.lock().unwrap().instantanea(mi_uid());
        assert_eq!(foto[0].ip, "192.0.2.1");
        assert_eq!(foto[0].domain, None);
    }

    /// Arma una respuesta DNS con una A de `ip` para `dominio`, para sembrar el
    /// snoop en las pruebas del lector.
    fn respuesta_dns(dominio: &[&str], ip: [u8; 4]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        m.extend_from_slice(&0x8180u16.to_be_bytes()); // flags
        m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        m.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        m.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        m.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for parte in dominio {
            m.push(parte.len() as u8);
            m.extend_from_slice(parte.as_bytes());
        }
        m.push(0); // fin del QNAME
        m.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        m.extend_from_slice(&[0xC0, 12]); // NAME: puntero al QNAME
        m.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        m.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        m.extend_from_slice(&300u32.to_be_bytes()); // TTL
        m.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        m.extend_from_slice(&ip);
        m
    }

    /// Un buffer corto no se procesa: `None`, sin tocar el modelo.
    #[test]
    fn un_evento_corto_no_se_procesa() {
        let modelo = modelo_nuevo();
        let cache = cache_nueva();
        let dns = modelo_dns_nuevo();
        assert_eq!(procesar_evento(&[0u8; 8], &modelo, &cache, &dns, 1), None);
        assert!(modelo.lock().unwrap().instantanea(mi_uid()).is_empty());
    }

    /// `resolver_exe` lee `/proc/<pid>/exe` cuando el pid no está en la caché:
    /// contra el propio proceso de la prueba da su ejecutable real.
    #[test]
    fn resolver_exe_cae_a_proc_cuando_no_esta_en_la_cache() {
        let cache = cache_nueva();
        let exe = resolver_exe(&cache, std::process::id());
        assert!(!exe.is_empty());
        assert!(
            !exe.starts_with("pid "),
            "tenía que resolverlo por /proc: {exe}"
        );
    }

    /// Y usa la caché del conector cuando el pid está anotado ahí (la ruta del
    /// `exec`, que es lo que se prefiere).
    #[test]
    fn resolver_exe_prefiere_la_cache_del_conector() {
        let cache = cache_nueva();
        // `anotar` guarda el ejecutable del proceso de la prueba (está bajo /home).
        crate::procesos::anotar(&cache, std::process::id());
        let exe = resolver_exe(&cache, std::process::id());
        assert!(!exe.is_empty());
        assert!(!exe.starts_with("pid "));
    }

    /// Un pid que ya no existe y no está en la caché se nombra por su número: una
    /// fila con el número es mejor que una sin nombre.
    #[test]
    fn resolver_exe_nombra_por_el_pid_si_no_hay_nada() {
        let cache = cache_nueva();
        assert_eq!(resolver_exe(&cache, u32::MAX), format!("pid {}", u32::MAX));
    }
}
