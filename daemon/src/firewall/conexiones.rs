//! El modelo en memoria del mapa de conexiones en vivo (M1 del #93).
//!
//! # Qué separa este módulo
//!
//! Lo testeable sin root vive acá: el **parseo** de los bytes crudos que emite el
//! programa BPF por el ring buffer, y el **modelo acotado** que los agrupa por
//! `(uid, exe, ip, puerto, proto)` con un techo rolling. El I/O privilegiado —leer
//! el ring buffer, resolver el ejecutable de un pid— vive en el adapter
//! [`super::mapa`], que necesita root y no se cubre, igual que `escuchar` en
//! `procesos.rs`.
//!
//! # Observacional y efímero
//!
//! El modelo vive **sólo en memoria** y se desvanece al reiniciar (decisión 5 del
//! diseño). No persiste nada: no es un registro de tráfico, es la foto de lo que
//! está pasando ahora. `count` y `last_seen_secs` existen para agrupar y ordenar
//! en la pantalla, no para llevar historia.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use vasak_permissions_protocol::ObservedConnection;

/// El tamaño exacto, en bytes, del `ConnectionEvent` que emite el programa BPF.
///
/// **Tiene que coincidir** con el `#[repr(C)]` de `firewall-ebpf/src/main.rs`
/// (32 bytes con relleno explícito). Una prueba lee la fuente del programa y ata
/// los desplazamientos a este parser, igual que la clave del mapa `BLOCKED`.
pub const EVENTO_LEN: usize = 32;

/// Las dos familias que el evento distingue, como las escribe el programa BPF.
const AF_INET6: u8 = 10;

/// El valor que el programa BPF pone en `verdict` cuando cortó la conexión.
const DENY: u8 = 1;

/// Los protocolos que se nombran; el resto cae en `other`.
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Un evento del ring buffer, ya parseado de los bytes pero **sin** el ejecutable:
/// eso lo pone el lector enriqueciendo con el pid (caché o `/proc`), porque pide
/// I/O y queda fuera de esta lógica pura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventoConexion {
    pub uid: u32,
    pub tgid: u32,
    pub ip: String,
    pub port: u16,
    pub proto: &'static str,
    pub bloqueado: bool,
}

/// Parsea un evento crudo del ring buffer. `None` si el buffer es más corto que
/// un evento —nunca debería pasar (el programa reserva el struct entero), pero no
/// se lee de más—.
///
/// Los desplazamientos son los del `#[repr(C)] ConnectionEvent` del programa BPF:
/// `uid`(0), `tgid`(4), `dst`(8..24), `port`(24), `family`(26), `proto`(27),
/// `verdict`(28), relleno(29..32). Todo little-endian, como el target BPF y el
/// host.
pub fn parsear(bytes: &[u8]) -> Option<EventoConexion> {
    if bytes.len() < EVENTO_LEN {
        return None;
    }
    let uid = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let tgid = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let dst: [u8; 16] = bytes[8..24].try_into().ok()?;
    let port = u16::from_le_bytes(bytes[24..26].try_into().ok()?);
    let family = bytes[26];
    let proto = bytes[27];
    let verdict = bytes[28];

    let ip = if family == AF_INET6 {
        Ipv6Addr::from(dst).to_string()
    } else {
        Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]).to_string()
    };

    Some(EventoConexion {
        uid,
        tgid,
        ip,
        port,
        proto: proto_nombre(proto),
        bloqueado: verdict == DENY,
    })
}

/// El nombre del protocolo del byte del socket. `other` para lo que no sea TCP ni
/// UDP (o 0, que algunos kernels dan si el socket todavía no lo fijó).
fn proto_nombre(proto: u8) -> &'static str {
    match proto {
        IPPROTO_TCP => "tcp",
        IPPROTO_UDP => "udp",
        _ => "other",
    }
}

/// Techo de destinos recordados a la vez, en todo el modelo.
///
/// Una sesión activa abre muchas conexiones; sin techo el mapa crecería sin fin y
/// la pantalla se volvería inservible. Al pasarlo, se descarta el destino visto
/// hace más tiempo (rolling), igual que `procesos.rs` acota su caché. Es sólo
/// memoria, así que un número holgado alcanza.
const MAXIMO: usize = 1024;

/// La clave de deduplicación de un destino: el mismo `(uid, exe, ip, puerto,
/// proto)` es una sola fila que cuenta repeticiones, no mil filas iguales.
type Clave = (u32, String, String, u16, &'static str);

/// El mapa de conexiones en vivo: por destino único, un [`ObservedConnection`]
/// con su conteo y su última vez. Acotado y en memoria.
#[derive(Default)]
pub struct ModeloConexiones {
    registros: HashMap<Clave, ObservedConnection>,
}

impl ModeloConexiones {
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Observa una conexión ya enriquecida con el ejecutable. Devuelve `true` la
    /// **primera** vez que se ve esa tupla: es cuando corresponde emitir la señal
    /// `ConnectionObserved` (las repeticiones no son noticia nueva).
    ///
    /// `ahora` son segundos desde el epoch, inyectado para poder probar el orden y
    /// el desalojo sin depender del reloj.
    ///
    /// `domain` es el nombre que el snoop de DNS (M2) ató a la IP de destino, o
    /// `None` si no hay uno reciente —una IP literal, una app con su propio DoH, o
    /// una respuesta ya vencida—: ahí la fila se muestra por IP. El dominio no es
    /// parte de la identidad de la fila (la clave sigue siendo
    /// `(uid, exe, ip, puerto, proto)`): es un dato que se enriquece y que puede
    /// llegar a conocerse recién después de la primera conexión.
    pub fn observar(
        &mut self,
        binary_path: String,
        evento: &EventoConexion,
        domain: Option<String>,
        ahora: u64,
    ) -> bool {
        let clave = (
            evento.uid,
            binary_path.clone(),
            evento.ip.clone(),
            evento.port,
            evento.proto,
        );

        if let Some(registro) = self.registros.get_mut(&clave) {
            registro.count = registro.count.saturating_add(1);
            registro.last_seen_secs = ahora;
            // El veredicto puede cambiar entre dos conexiones al mismo destino —el
            // usuario cortó o restauró la red—: vale el último visto.
            registro.allowed = !evento.bloqueado;
            // El dominio puede conocerse recién ahora (la respuesta DNS llegó
            // después de la primera conexión), así que se completa si apareció; una
            // respuesta nueva que lo cambie también gana. No se borra con `None`:
            // una entrada vencida no debe tapar el nombre que ya se mostraba.
            if domain.is_some() {
                registro.domain = domain;
            }
            return false;
        }

        if self.registros.len() >= MAXIMO {
            self.desalojar_mas_viejo();
        }

        self.registros.insert(
            clave,
            ObservedConnection {
                uid: evento.uid,
                binary_path,
                ip: evento.ip.clone(),
                port: evento.port,
                proto: evento.proto.to_string(),
                allowed: !evento.bloqueado,
                count: 1,
                last_seen_secs: ahora,
                domain,
            },
        );
        true
    }

    /// Saca el destino visto hace más tiempo, para hacer lugar a uno nuevo.
    fn desalojar_mas_viejo(&mut self) {
        if let Some(clave) = self
            .registros
            .iter()
            .min_by_key(|(_, c)| c.last_seen_secs)
            .map(|(k, _)| k.clone())
        {
            self.registros.remove(&clave);
        }
    }

    /// La foto de las conexiones de **un** usuario, lo más reciente primero. Se
    /// filtra por uid como `list_blocked`: un cliente sin privilegios nunca ve los
    /// destinos de otra persona.
    pub fn instantanea(&self, uid: u32) -> Vec<ObservedConnection> {
        let mut filas: Vec<ObservedConnection> = self
            .registros
            .values()
            .filter(|c| c.uid == uid)
            .cloned()
            .collect();
        filas.sort_by_key(|c| std::cmp::Reverse(c.last_seen_secs));
        filas
    }
}

/// El modelo compartido entre el lector del ring buffer (un task) y
/// `ListConnections` (el servicio). `Mutex` de `std` y no de tokio: las
/// operaciones son cortas y sincrónicas, y nunca se sostiene el candado a través
/// de un `.await`.
pub type ModeloCompartido = std::sync::Arc<std::sync::Mutex<ModeloConexiones>>;

pub fn modelo_nuevo() -> ModeloCompartido {
    std::sync::Arc::new(std::sync::Mutex::new(ModeloConexiones::nuevo()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arma los 32 bytes de un `ConnectionEvent` como los escribe el programa BPF,
    /// para ejercitar el parser sin cargar BPF. Si este helper y el `#[repr(C)]`
    /// del programa se separan, la prueba de correspondencia de abajo lo delata.
    fn bytes_evento(
        uid: u32,
        tgid: u32,
        dst: [u8; 16],
        port: u16,
        family: u8,
        proto: u8,
        verdict: u8,
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(EVENTO_LEN);
        m.extend_from_slice(&uid.to_le_bytes());
        m.extend_from_slice(&tgid.to_le_bytes());
        m.extend_from_slice(&dst);
        m.extend_from_slice(&port.to_le_bytes());
        m.push(family);
        m.push(proto);
        m.push(verdict);
        m.extend_from_slice(&[0u8; 3]);
        assert_eq!(
            m.len(),
            EVENTO_LEN,
            "el evento de prueba no mide {EVENTO_LEN}"
        );
        m
    }

    #[test]
    fn parsea_una_conexion_ipv4_tcp_permitida() {
        let dst = [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ev = parsear(&bytes_evento(1000, 4242, dst, 443, 2, 6, 0)).expect("parsea");
        assert_eq!(ev.uid, 1000);
        assert_eq!(ev.tgid, 4242);
        assert_eq!(ev.ip, "192.0.2.1");
        assert_eq!(ev.port, 443);
        assert_eq!(ev.proto, "tcp");
        assert!(!ev.bloqueado);
    }

    #[test]
    fn parsea_una_conexion_ipv6_udp_bloqueada() {
        // 2001:db8::1
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let ev = parsear(&bytes_evento(1001, 77, dst, 53, 10, 17, 1)).expect("parsea");
        assert_eq!(ev.ip, "2001:db8::1");
        assert_eq!(ev.port, 53);
        assert_eq!(ev.proto, "udp");
        assert!(ev.bloqueado);
    }

    /// Un protocolo que no es TCP ni UDP cae en `other` en vez de inventar un
    /// nombre: el socket puede traer 0 si todavía no lo fijó.
    #[test]
    fn un_protocolo_desconocido_es_other() {
        let dst = [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parsear(&bytes_evento(1, 1, dst, 1, 2, 0, 0)).unwrap().proto,
            "other"
        );
        assert_eq!(
            parsear(&bytes_evento(1, 1, dst, 1, 2, 132, 0))
                .unwrap()
                .proto,
            "other"
        );
    }

    /// Un buffer más corto que un evento no lee de más: devuelve `None`.
    #[test]
    fn un_buffer_corto_no_lee_de_mas() {
        assert_eq!(parsear(&[]), None);
        assert_eq!(parsear(&[0u8; EVENTO_LEN - 1]), None);
    }

    /// El `#[repr(C)]` del programa BPF y los desplazamientos de `parsear` se
    /// separan sin que nada avise si alguien toca uno solo. Esta prueba lee la
    /// fuente del programa (siempre disponible, a diferencia del toolchain BPF) y
    /// exige que el struct tenga los campos en el orden y los tamaños que el parser
    /// supone, y que mida [`EVENTO_LEN`].
    #[test]
    fn la_fuente_bpf_define_el_evento_que_este_parser_supone() {
        let fuente = include_str!("../../../firewall-ebpf/src/main.rs");
        for campo in [
            "uid: u32,",
            "tgid: u32,",
            "dst: [u8; 16],",
            "port: u16,",
            "family: u8,",
            "proto: u8,",
            "verdict: u8,",
            "_pad: [u8; 3],",
        ] {
            assert!(
                fuente.contains(campo),
                "el ConnectionEvent del programa BPF ya no tiene «{campo}»; \
                 el parser de conexiones.rs quedó desincronizado"
            );
        }
        // El orden importa tanto como los campos: `uid` antes de `tgid`, `dst`
        // antes de `port`. Se comprueba que aparezcan en ese orden en la fuente.
        let pos = |s: &str| fuente.find(s).unwrap_or(usize::MAX);
        assert!(pos("uid: u32,") < pos("tgid: u32,"));
        assert!(pos("tgid: u32,") < pos("dst: [u8; 16],"));
        assert!(pos("dst: [u8; 16],") < pos("port: u16,"));
        assert!(pos("port: u16,") < pos("family: u8,"));
        assert!(pos("family: u8,") < pos("proto: u8,"));
        assert!(pos("proto: u8,") < pos("verdict: u8,"));
    }

    /// Los desplazamientos que `parsear` supone salen de la **fuente** del struct
    /// del BPF calculados como `repr(C)` (tamaño y alineación por campo), no de
    /// una lista de textos: si alguien cambia un tipo (`port: u32`) o inserta un
    /// campo, los offsets cambian y esto lo delata aunque la fuente siga
    /// «teniendo» cada nombre.
    #[test]
    fn el_layout_repr_c_de_la_fuente_bpf_coincide_con_los_desplazamientos_del_parser() {
        let fuente = include_str!("../../../firewall-ebpf/src/main.rs");
        let cuerpo = fuente
            .split("struct ConnectionEvent {")
            .nth(1)
            .and_then(|r| r.split("\n}").next())
            .expect("no se encontró struct ConnectionEvent");
        let mut offset = 0usize;
        let mut maxalign = 1usize;
        let mut offsets = Vec::new();
        for linea in cuerpo.lines().map(str::trim) {
            if linea.starts_with("//") || linea.is_empty() {
                continue;
            }
            let (nombre, tipo) = linea.trim_end_matches(',').split_once(": ").unwrap();
            let (tam, alin) = match tipo {
                "u8" => (1, 1),
                "u16" => (2, 2),
                "u32" => (4, 4),
                "[u8; 16]" => (16, 1),
                "[u8; 3]" => (3, 1),
                otro => panic!("tipo sin tamaño conocido en el evento: {otro}"),
            };
            offset = offset.next_multiple_of(alin);
            offsets.push((nombre.to_string(), offset));
            offset += tam;
            maxalign = maxalign.max(alin);
        }
        let total = offset.next_multiple_of(maxalign);
        assert_eq!(
            total, EVENTO_LEN,
            "el struct del BPF ya no mide {EVENTO_LEN}"
        );
        let esperado = [
            ("uid", 0),
            ("tgid", 4),
            ("dst", 8),
            ("port", 24),
            ("family", 26),
            ("proto", 27),
            ("verdict", 28),
            ("_pad", 29),
        ];
        let obtenido: Vec<(&str, usize)> = offsets.iter().map(|(n, o)| (n.as_str(), *o)).collect();
        assert_eq!(
            obtenido, esperado,
            "los offsets de parsear() quedaron viejos"
        );
    }

    /// El programa BPF no cambia el veredicto al emitir: `emit` no devuelve nada
    /// y el valor de retorno de `handle` sale sólo de `bloqueado`, que se calcula
    /// **antes** de emitir. No se puede cargar BPF sin root, así que se ata la
    /// forma de la fuente (la prueba root `firewall_integracion` ejerce el resto).
    #[test]
    fn la_emision_bpf_no_puede_alterar_el_veredicto() {
        let fuente = include_str!("../../../firewall-ebpf/src/main.rs");
        let firma = fuente
            .split("fn emit(")
            .nth(1)
            .and_then(|r| r.split('{').next())
            .expect("falta fn emit");
        assert!(!firma.contains("->"), "emit no debe devolver nada: {firma}");
        let handle = fuente.split("fn handle(").nth(1).expect("falta fn handle");
        let pos_calculo = handle.find("let bloqueado").expect("falta el cálculo");
        let pos_emit = handle.find("emit(ctx").expect("handle no emite");
        let pos_ret = handle.find("if bloqueado").expect("falta el retorno");
        assert!(pos_calculo < pos_emit && pos_emit < pos_ret);
        assert!(
            !handle[pos_emit..].contains("bloqueado ="),
            "el veredicto no se puede reescribir tras emitir"
        );
    }

    /// Para IPv4 sólo valen los primeros 4 bytes de `dst`: la basura del resto
    /// no puede colarse en la IP. Y sólo `verdict == 1` es bloqueo.
    #[test]
    fn ipv4_ignora_el_resto_de_dst_y_solo_el_veredicto_uno_bloquea() {
        let dst = [203, 0, 113, 7, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        let ev = parsear(&bytes_evento(5, 6, dst, 8080, 2, 6, 2)).unwrap();
        assert_eq!(ev.ip, "203.0.113.7");
        assert_eq!((ev.uid, ev.tgid, ev.port), (5, 6, 8080));
        assert!(!ev.bloqueado);
    }

    /// Un uid y un tgid distintos en IPv6 salen de sus desplazamientos: no se
    /// confunden entre sí ni con el puerto.
    #[test]
    fn ipv6_separa_uid_tgid_y_puerto() {
        let ev = parsear(&bytes_evento(
            0x0102_0304,
            0x0a0b_0c0d,
            [1; 16],
            0xabcd,
            10,
            6,
            0,
        ))
        .unwrap();
        assert_eq!(ev.uid, 0x0102_0304);
        assert_eq!(ev.tgid, 0x0a0b_0c0d);
        assert_eq!(ev.port, 0xabcd);
        assert_eq!(ev.proto, "tcp");
    }

    // ── El modelo acotado ─────────────────────────────────────────────────────

    fn evento(
        uid: u32,
        ip: &str,
        port: u16,
        proto: &'static str,
        bloqueado: bool,
    ) -> EventoConexion {
        EventoConexion {
            uid,
            tgid: 1,
            ip: ip.to_string(),
            port,
            proto,
            bloqueado,
        }
    }

    /// La primera vez que se ve un destino es «nuevo» (señal), y vuelve en la
    /// instantánea con conteo 1; repetirlo no es nuevo y suma al conteo.
    #[test]
    fn observar_cuenta_y_avisa_solo_la_primera_vez() {
        let mut m = ModeloConexiones::nuevo();
        let ev = evento(1000, "192.0.2.1", 443, "tcp", false);

        assert!(
            m.observar("/home/x/app".into(), &ev, None, 10),
            "la primera es nueva"
        );
        assert!(
            !m.observar("/home/x/app".into(), &ev, None, 11),
            "la segunda al mismo destino no es nueva"
        );

        let foto = m.instantanea(1000);
        assert_eq!(foto.len(), 1);
        assert_eq!(foto[0].count, 2);
        assert_eq!(foto[0].last_seen_secs, 11);
        assert_eq!(foto[0].ip, "192.0.2.1");
        assert!(foto[0].allowed);
    }

    /// Dos destinos distintos del mismo exe son dos filas; cambiar el puerto, el
    /// protocolo o la IP es otro destino.
    #[test]
    fn destinos_distintos_son_filas_distintas() {
        let mut m = ModeloConexiones::nuevo();
        assert!(m.observar(
            "/home/x/app".into(),
            &evento(1000, "192.0.2.1", 443, "tcp", false),
            None,
            1
        ));
        assert!(m.observar(
            "/home/x/app".into(),
            &evento(1000, "192.0.2.1", 80, "tcp", false),
            None,
            1
        ));
        assert!(m.observar(
            "/home/x/app".into(),
            &evento(1000, "192.0.2.1", 443, "udp", false),
            None,
            1
        ));
        assert!(m.observar(
            "/home/x/app".into(),
            &evento(1000, "198.51.100.9", 443, "tcp", false),
            None,
            1
        ));
        assert_eq!(m.instantanea(1000).len(), 4);
    }

    /// La instantánea se filtra por uid: un cliente no ve los destinos de otra
    /// persona, y vienen ordenados por lo más reciente primero.
    #[test]
    fn la_instantanea_filtra_por_uid_y_ordena_por_recencia() {
        let mut m = ModeloConexiones::nuevo();
        m.observar(
            "/home/a/app".into(),
            &evento(1000, "192.0.2.1", 1, "tcp", false),
            None,
            5,
        );
        m.observar(
            "/home/a/app".into(),
            &evento(1000, "192.0.2.2", 2, "tcp", false),
            None,
            9,
        );
        m.observar(
            "/home/b/app".into(),
            &evento(1001, "203.0.113.5", 3, "tcp", false),
            None,
            7,
        );

        let foto = m.instantanea(1000);
        assert_eq!(foto.len(), 2, "sólo las del uid 1000");
        assert!(foto.iter().all(|c| c.uid == 1000));
        assert_eq!(foto[0].ip, "192.0.2.2", "la más reciente primero");
        assert_eq!(foto[1].ip, "192.0.2.1");

        assert_eq!(m.instantanea(1001).len(), 1);
        assert!(
            m.instantanea(4242).is_empty(),
            "un uid sin conexiones no ve nada"
        );
    }

    /// El veredicto del último evento manda: una app que se corta pasa de
    /// permitida a bloqueada en la misma fila.
    #[test]
    fn el_ultimo_veredicto_manda() {
        let mut m = ModeloConexiones::nuevo();
        m.observar(
            "/home/x/app".into(),
            &evento(1000, "192.0.2.1", 443, "tcp", false),
            None,
            1,
        );
        assert!(m.instantanea(1000)[0].allowed);
        m.observar(
            "/home/x/app".into(),
            &evento(1000, "192.0.2.1", 443, "tcp", true),
            None,
            2,
        );
        assert!(
            !m.instantanea(1000)[0].allowed,
            "el corte posterior se refleja"
        );
    }

    /// El dominio del snoop de DNS se guarda en la fila al observar, y se muestra
    /// junto a la IP. La clave de la fila no cambia por el dominio.
    #[test]
    fn el_dominio_se_guarda_en_la_fila() {
        let mut m = ModeloConexiones::nuevo();
        m.observar(
            "/home/x/app".into(),
            &evento(1000, "93.184.216.34", 443, "tcp", false),
            Some("example.com".into()),
            1,
        );
        let foto = m.instantanea(1000);
        assert_eq!(foto.len(), 1);
        assert_eq!(foto[0].domain.as_deref(), Some("example.com"));
        assert_eq!(
            foto[0].ip, "93.184.216.34",
            "la IP se conserva junto al dominio"
        );
    }

    /// El dominio puede conocerse recién tras la primera conexión (la respuesta
    /// DNS llegó después): la repetición lo completa, y un `None` posterior —una
    /// entrada vencida— no borra el nombre ya mostrado.
    #[test]
    fn el_dominio_se_completa_despues_y_no_se_borra_con_none() {
        let mut m = ModeloConexiones::nuevo();
        let ev = evento(1000, "93.184.216.34", 443, "tcp", false);
        // Primera conexión sin dominio conocido todavía.
        m.observar("/home/x/app".into(), &ev, None, 1);
        assert_eq!(m.instantanea(1000)[0].domain, None);
        // La respuesta DNS se vio después: la próxima conexión al mismo destino
        // completa el dominio.
        m.observar("/home/x/app".into(), &ev, Some("example.com".into()), 2);
        assert_eq!(
            m.instantanea(1000)[0].domain.as_deref(),
            Some("example.com")
        );
        // Una conexión posterior sin dominio (la entrada DNS venció) no lo borra.
        m.observar("/home/x/app".into(), &ev, None, 3);
        assert_eq!(
            m.instantanea(1000)[0].domain.as_deref(),
            Some("example.com")
        );
    }

    /// Al pasar el techo, se desaloja el destino visto hace más tiempo —no uno
    /// cualquiera— y el modelo no crece sin fin.
    #[test]
    fn al_pasar_el_techo_se_desaloja_el_mas_viejo() {
        let mut m = ModeloConexiones::nuevo();
        // Llenar el modelo, cada destino visto en un segundo distinto.
        for i in 0..MAXIMO {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            m.observar(
                "/home/x/app".into(),
                &evento(1000, &ip, 443, "tcp", false),
                None,
                i as u64,
            );
        }
        assert_eq!(m.instantanea(1000).len(), MAXIMO);

        // El más viejo es el del segundo 0 (10.0.0.0). Uno nuevo lo desaloja.
        m.observar(
            "/home/x/app".into(),
            &evento(1000, "203.0.113.1", 443, "tcp", false),
            None,
            999_999,
        );
        let foto = m.instantanea(1000);
        assert_eq!(foto.len(), MAXIMO, "el techo se mantiene");
        assert!(
            !foto.iter().any(|c| c.ip == "10.0.0.0"),
            "se desalojó el visto hace más tiempo"
        );
        assert!(foto.iter().any(|c| c.ip == "203.0.113.1"), "entró el nuevo");
    }
    /// Repetir un destino que ya está **no desaloja** a nadie aunque el modelo
    /// esté en el techo, y refresca su recencia: el desalojo siguiente se lleva
    /// al que ahora es el más viejo, no al que se acaba de volver a ver.
    #[test]
    fn repetir_un_destino_en_el_techo_no_desaloja_y_lo_rejuvenece() {
        let mut m = ModeloConexiones::nuevo();
        for i in 0..MAXIMO {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            m.observar(
                "/a".into(),
                &evento(1000, &ip, 1, "tcp", false),
                None,
                i as u64,
            );
        }
        // El más viejo (10.0.0.0, t=0) se vuelve a ver: sigue habiendo MAXIMO.
        assert!(!m.observar(
            "/a".into(),
            &evento(1000, "10.0.0.0", 1, "tcp", false),
            None,
            5000
        ));
        assert_eq!(m.instantanea(1000).len(), MAXIMO);
        // Uno nuevo desaloja ahora a 10.0.0.1 (t=1), no a 10.0.0.0.
        assert!(m.observar(
            "/a".into(),
            &evento(1000, "203.0.113.1", 1, "tcp", false),
            None,
            6000
        ));
        let foto = m.instantanea(1000);
        assert_eq!(foto.len(), MAXIMO);
        assert!(
            foto.iter().any(|c| c.ip == "10.0.0.0"),
            "el rejuvenecido sobrevive"
        );
        assert!(
            !foto.iter().any(|c| c.ip == "10.0.0.1"),
            "se fue el más viejo real"
        );
    }

    /// El techo es de todo el modelo, no por uid, y el filtro de uid sigue
    /// valiendo tras desalojar: un uid nunca ve filas de otro.
    #[test]
    fn el_techo_es_global_y_el_aislamiento_por_uid_se_mantiene() {
        let mut m = ModeloConexiones::nuevo();
        for i in 0..(MAXIMO + 10) {
            let uid = 1000 + (i % 2) as u32;
            let ip = format!("10.1.{}.{}", i / 256, i % 256);
            m.observar(
                "/a".into(),
                &evento(uid, &ip, 1, "tcp", false),
                None,
                i as u64,
            );
        }
        let (a, b) = (m.instantanea(1000), m.instantanea(1001));
        assert_eq!(a.len() + b.len(), MAXIMO);
        assert!(a.iter().all(|c| c.uid == 1000));
        assert!(b.iter().all(|c| c.uid == 1001));
    }
}
