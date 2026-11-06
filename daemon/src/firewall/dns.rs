//! El snoop de DNS del cortafuegos: observa las respuestas del resolvedor y arma
//! el puente `(uid, IP) → dominio` que enriquece el mapa en vivo (M2 del #93).
//!
//! # Qué separa este módulo
//!
//! Lo testeable sin root —y sin red— vive acá: el **parseo** de una respuesta DNS
//! a sus registros A/AAAA, el **destripado** de un mensaje NFLOG hasta esos bytes,
//! y el **modelo acotado** `(uid, IP) → dominio` con vencimiento por TTL. El I/O
//! privilegiado —instalar la regla nftables, leer el socket NFLOG— vive en el
//! adapter [`escuchar`], que necesita `CAP_NET_ADMIN` y no se cubre, igual que
//! `escuchar` en `procesos.rs`.
//!
//! # El daemon NUNCA resuelve ni abre un socket de red
//!
//! Esta es la frontera del diseño (sección «Reglas por dominio» del #93): el
//! daemon **observa** las respuestas que el resolvedor del sistema ya produjo, por
//! NFLOG sobre `AF_NETLINK` (ya permitido en la unidad), y nunca manda una
//! consulta ni abre un `AF_INET`. Darle salida de red a un servicio root es justo
//! lo que se evita. Si no puede instalar la regla (sin `CAP_NET_ADMIN`, sin `nft`)
//! degrada ruidoso y el mapa sigue andando **sin** dominios.
//!
//! # Atribución por uid y el stub de systemd-resolved
//!
//! La regla registra el tráfico DNS con `meta skuid`, el uid del socket local. Con
//! systemd-resolved el stub escucha en `127.0.0.53`, así que la respuesta
//! `127.0.0.53 → app` es tráfico **de loopback** cuyo socket es el de la app: su
//! `skuid` es el de la app, que es lo que queremos. El tramo `resolved → upstream`
//! lleva el uid de `systemd-resolve`; esas entradas caen bajo una clave
//! `(uid_de_resolved, IP)` que ninguna app consulta, así que son ruido inofensivo.
//!
//! # Observacional y efímero
//!
//! El modelo vive **sólo en memoria** y se desvanece al reiniciar: no es un
//! registro de tráfico ni de navegación, es la foto reciente de qué nombre ató
//! cada app a cada IP, para mostrarlo al lado de la conexión. Nada se persiste.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Un registro A/AAAA de una respuesta DNS: a qué IP (en texto, v4 o v6) apunta el
/// nombre consultado, y por cuántos segundos el resolvedor lo dio por válido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistroDns {
    pub ip: String,
    pub ttl: u32,
}

/// Una respuesta DNS ya parseada: el **nombre consultado** (de la sección de
/// preguntas, no el de cada registro) y las IPs que resolvió.
///
/// Se atribuye el nombre consultado y no el `NAME` de cada registro a propósito:
/// una respuesta encadena CNAME (`www.sitio.com` → `sitio.cdn.net` → A), y lo que
/// la persona reconoce —y la app pidió— es el primero. Mapear cada IP al nombre
/// consultado sigue la cadena sin tener que resolverla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaDns {
    pub dominio: String,
    pub registros: Vec<RegistroDns>,
}

/// Los tipos de registro que nos interesan, como los numera el protocolo DNS.
const TIPO_A: u16 = 1;
const TIPO_AAAA: u16 = 28;

/// El encabezado DNS mide 12 bytes: ID, flags, y los cuatro contadores de sección.
const ENCABEZADO_DNS: usize = 12;

/// Lee un nombre DNS desde `inicio`, devolviendo el nombre en puntos y la posición
/// **justo después** de su codificación en `inicio`.
///
/// Un nombre es una secuencia de etiquetas `len` + bytes, terminada en un `0x00`, y
/// puede llevar un **puntero de compresión** (los dos bits altos del largo en 1):
/// el nombre continúa en otro desplazamiento del mensaje. Se siguen los punteros
/// para armar el texto, pero la posición devuelta es la que sigue a la primera
/// terminación o puntero en `inicio` —que es lo que hace falta para avanzar al
/// campo siguiente del registro—.
///
/// Un tope de saltos corta los punteros en bucle (un mensaje malicioso que apunte
/// a sí mismo), así que esto nunca cicla ni lee de más: ante cualquier byte fuera
/// de rango devuelve `None`.
fn leer_nombre(msg: &[u8], inicio: usize) -> Option<(String, usize)> {
    let mut etiquetas: Vec<String> = Vec::new();
    let mut pos = inicio;
    let mut fin: Option<usize> = None;
    let mut saltos = 0u32;
    // Un nombre DNS mide ≤255 bytes (RFC 1035 §3.1). Sin esta cota, el tope de
    // saltos corta el bucle pero recién tras construir el nombre: un puntero que
    // relee un campo denso de etiquetas amplifica ~126x (8 MB por paquete de 64
    // KB) antes de devolver None — DoS de recursos contra un daemon root.
    let mut largo_total = 0usize;

    loop {
        let largo = *msg.get(pos)? as usize;
        if largo & 0xC0 == 0xC0 {
            // Puntero de compresión: dos bytes, y el nombre sigue en el destino.
            let bajo = *msg.get(pos + 1)? as usize;
            let destino = ((largo & 0x3F) << 8) | bajo;
            fin.get_or_insert(pos + 2);
            saltos += 1;
            if saltos > 128 || destino >= msg.len() {
                return None;
            }
            pos = destino;
        } else if largo == 0 {
            fin.get_or_insert(pos + 1);
            break;
        } else {
            largo_total += largo + 1;
            if largo_total > 255 {
                return None;
            }
            pos += 1;
            let etiqueta = msg.get(pos..pos + largo)?;
            etiquetas.push(String::from_utf8_lossy(etiqueta).into_owned());
            pos += largo;
        }
    }

    Some((etiquetas.join("."), fin.unwrap_or(pos)))
}

/// Parsea una respuesta DNS cruda a su nombre consultado y sus registros A/AAAA.
///
/// `None` si el mensaje no tiene al menos una pregunta y un A/AAAA utilizable, o si
/// está truncado/malformado en cualquier punto: un paquete recortado **no** rompe
/// —se devuelve `None` y el mapa sigue sin ese dominio—. No se exige el bit de
/// respuesta: el snoop sólo registra respuestas, y un parser tolerante es más
/// simple de razonar que uno que valide banderas que el kernel ya filtró.
pub fn parsear_respuesta(msg: &[u8]) -> Option<RespuestaDns> {
    if msg.len() < ENCABEZADO_DNS {
        return None;
    }
    let preguntas = u16::from_be_bytes([msg[4], msg[5]]);
    let respuestas = u16::from_be_bytes([msg[6], msg[7]]);
    if preguntas == 0 {
        return None;
    }

    // La primera pregunta da el nombre que la app consultó.
    let (dominio, mut pos) = leer_nombre(msg, ENCABEZADO_DNS)?;
    pos = pos.checked_add(4)?; // QTYPE(2) + QCLASS(2)

    // Saltar el resto de las preguntas (raro, pero el formato las permite).
    for _ in 1..preguntas {
        let (_, siguiente) = leer_nombre(msg, pos)?;
        pos = siguiente.checked_add(4)?;
    }

    let mut registros = Vec::new();
    for _ in 0..respuestas {
        let (_, despues_del_nombre) = leer_nombre(msg, pos)?;
        pos = despues_del_nombre;
        let tipo = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
        // CLASS en pos+2..pos+4, se ignora (siempre IN en la práctica).
        let ttl = u32::from_be_bytes([
            *msg.get(pos + 4)?,
            *msg.get(pos + 5)?,
            *msg.get(pos + 6)?,
            *msg.get(pos + 7)?,
        ]);
        let rdlen = u16::from_be_bytes([*msg.get(pos + 8)?, *msg.get(pos + 9)?]) as usize;
        let rdata_ini = pos + 10;
        let rdata = msg.get(rdata_ini..rdata_ini.checked_add(rdlen)?)?;

        match (tipo, rdlen) {
            (TIPO_A, 4) => registros.push(RegistroDns {
                ip: Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
                ttl,
            }),
            (TIPO_AAAA, 16) => {
                let octetos: [u8; 16] = rdata.try_into().ok()?;
                registros.push(RegistroDns {
                    ip: Ipv6Addr::from(octetos).to_string(),
                    ttl,
                });
            }
            _ => {}
        }
        pos = rdata_ini + rdlen;
    }

    if registros.is_empty() {
        return None; // una respuesta sin A/AAAA (sólo CNAME, NXDOMAIN…) no mapea nada
    }
    Some(RespuestaDns { dominio, registros })
}

/// Techo de pares `(uid, IP)` recordados a la vez.
///
/// Como el del mapa de conexiones: una sesión activa resuelve muchos nombres, y
/// sin techo esto crecería sin fin. Al pasarlo se desaloja la entrada que **vence
/// antes** —la más cerca de quedar obsoleta—, no una cualquiera.
const MAXIMO: usize = 4096;

/// Piso del TTL con el que se recuerda una entrada.
///
/// Un TTL de 0 (o muy bajo) es válido en DNS y significa «no lo caches», pero la
/// conexión que sigue a la consulta llega en segundos: si venciera al instante, el
/// mapa no llegaría a mostrar el dominio de la conexión que la respuesta justo
/// habilitó. Se le da un piso corto para que siga siendo útil ese ratito. Es sólo
/// para mostrar, no para decidir nada.
const TTL_PISO: u64 = 30;

/// Techo del TTL: un registro con TTL de días no clava una entrada en memoria por
/// días. Se recorta para que el modelo se renueve y una IP reasignada a otro
/// dominio no muestre el viejo para siempre.
const TTL_TECHO: u64 = 3600;

/// La clave: el uid que resolvió y la IP resuelta. Atar por IP es lo que permite
/// casar contra el destino exacto del `connect()` sin resolver nada el daemon.
type Clave = (u32, String);

/// Una entrada del snoop: a qué dominio apunta la IP y hasta cuándo vale, en
/// segundos desde el epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entrada {
    dominio: String,
    vence: u64,
}

/// El modelo `(uid, IP) → dominio` con vencimiento por TTL, acotado y en memoria.
#[derive(Default)]
pub struct ModeloDns {
    registros: HashMap<Clave, Entrada>,
}

impl ModeloDns {
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Anota todas las IPs de una respuesta como resueltas por `uid` hacia
    /// `dominio`, con su vencimiento. `ahora` son segundos desde el epoch,
    /// inyectado para probar el TTL sin depender del reloj.
    ///
    /// Si llega otra respuesta para la misma `(uid, IP)` —la IP ahora apunta a
    /// otro nombre— gana la última: refleja la resolución más reciente, que es la
    /// que la app va a usar.
    pub fn observar(&mut self, uid: u32, respuesta: &RespuestaDns, ahora: u64) {
        for registro in &respuesta.registros {
            let vida = (registro.ttl as u64).clamp(TTL_PISO, TTL_TECHO);
            let vence = ahora.saturating_add(vida);
            let clave = (uid, registro.ip.clone());
            if !self.registros.contains_key(&clave) && self.registros.len() >= MAXIMO {
                self.desalojar_el_que_vence_antes();
            }
            self.registros.insert(
                clave,
                Entrada {
                    dominio: respuesta.dominio.clone(),
                    vence,
                },
            );
        }
    }

    /// El dominio que `uid` ató a `ip`, si hay una entrada **no vencida**. `None`
    /// si nunca se vio esa IP para ese uid o si su TTL ya pasó: una entrada vencida
    /// no se usa —la IP pudo reasignarse— y la fila del mapa se muestra por IP.
    pub fn dominio_de(&self, uid: u32, ip: &str, ahora: u64) -> Option<String> {
        self.registros
            .get(&(uid, ip.to_string()))
            .filter(|e| e.vence > ahora)
            .map(|e| e.dominio.clone())
    }

    /// Saca la entrada que vence antes, para hacer lugar a una nueva.
    fn desalojar_el_que_vence_antes(&mut self) {
        if let Some(clave) = self
            .registros
            .iter()
            .min_by_key(|(_, e)| e.vence)
            .map(|(k, _)| k.clone())
        {
            self.registros.remove(&clave);
        }
    }
}

/// El modelo compartido entre el lector NFLOG (un hilo) y el lector del ring
/// buffer del mapa (un task), que lo consulta para enriquecer cada conexión.
/// `Mutex` de `std`: las operaciones son cortas y sincrónicas, y el candado nunca
/// se sostiene a través de un `.await`.
pub type ModeloDnsCompartido = std::sync::Arc<std::sync::Mutex<ModeloDns>>;

pub fn modelo_dns_nuevo() -> ModeloDnsCompartido {
    std::sync::Arc::new(std::sync::Mutex::new(ModeloDns::nuevo()))
}

// ── El lector NFLOG: el adapter privilegiado ──────────────────────────────────
//
// Instala la regla nftables que registra el tráfico DNS a un grupo NFLOG y lee
// los mensajes por `AF_NETLINK`. Como `escuchar` en `procesos.rs`, es I/O
// privilegiado que el CI no corre: pide `CAP_NET_ADMIN` y un `nft` presente. Lo
// probable que **sí** se cubre es el destripado del mensaje —[`dns_de_nflog`],
// [`dns_de_l3`]— y el texto de la regla, que es donde está la aritmética de
// desplazamientos propensa a error; el socket en sí lo ejercita el uso real.

/// La familia del socket netlink de netfilter, por la que llega NFLOG.
const NETLINK_NETFILTER: i32 = 12;
/// El subsistema nfnetlink del log (nfnetlink_log) y sus dos tipos de mensaje.
const NFNL_SUBSYS_ULOG: u16 = 5;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
/// Los comandos y modos de configuración que se le mandan al grupo.
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;
/// Los atributos de la configuración y del paquete que leemos.
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_UID: u16 = 11;
const NLM_F_REQUEST: u16 = 1;
const IPPROTO_UDP: u8 = 17;

/// El grupo NFLOG al que la regla manda el tráfico DNS. Un número propio y alto
/// para no pisar a otro usuario de NFLOG del sistema.
const GRUPO_NFLOG: u16 = 0x5653;

/// El nombre de la tabla nftables que el daemon instala y destruye.
const TABLA_NFT: &str = "vasak_dns_snoop";

/// El puerto del DNS.
const PUERTO_DNS: u16 = 53;

/// La regla nftables que registra las **respuestas** DNS al grupo NFLOG.
///
/// Sólo **registra** (`log group`), nunca descarta: el veredicto de M0/M1 queda
/// idéntico, esto no bloquea ni permite nada. Engancha en `input` y filtra
/// `sport 53` para quedarse con las respuestas que llegan a un socket local —con
/// systemd-resolved, el stub en `127.0.0.53` hace que la respuesta a la app sea
/// tráfico de loopback que también entra por `input`—. NFLOG adjunta el uid del
/// socket que la recibe (la app), que es por donde se atribuye.
///
/// `destroy` antes de `table` la vuelve idempotente al reiniciar el daemon (no
/// falla si la tabla no existe, nft ≥ 1.0.2).
///
/// shortcut: sólo UDP; el DNS sobre TCP no se destripa (ver [`dns_de_l3`]). Subir
/// a TCP cuando aparezca un resolvedor que lo use por defecto.
fn regla_nft(grupo: u16) -> String {
    format!(
        "destroy table inet {TABLA_NFT}\n\
         table inet {TABLA_NFT} {{\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority 0; policy accept;\n\
         \t\tudp sport {PUERTO_DNS} log group {grupo}\n\
         \t}}\n\
         }}\n"
    )
}

/// Instala la regla con `nft -f -`. Degrada ruidoso: si `nft` falta o la regla no
/// aplica (sin `CAP_NET_ADMIN`, kernel sin nftables), se registra y se devuelve
/// `false` —el mapa en vivo sigue andando, sin dominios—.
fn instalar_regla() -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut hijo = match Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(hijo) => hijo,
        Err(e) => {
            tracing::warn!(
                "No se pudo ejecutar «nft» para el snoop de DNS ({e}); \
                 el mapa en vivo no va a mostrar dominios"
            );
            return false;
        }
    };

    if let Some(mut stdin) = hijo.stdin.take() {
        if let Err(e) = stdin.write_all(regla_nft(GRUPO_NFLOG).as_bytes()) {
            tracing::warn!("No se pudo escribir la regla de DNS a «nft» ({e})");
            return false;
        }
    }

    match hijo.wait_with_output() {
        Ok(salida) if salida.status.success() => true,
        Ok(salida) => {
            tracing::warn!(
                "«nft» rechazó la regla del snoop de DNS ({}); el mapa en vivo \
                 no va a mostrar dominios: {}",
                salida.status,
                String::from_utf8_lossy(&salida.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("«nft» no terminó al instalar la regla de DNS ({e})");
            false
        }
    }
}

/// Saca el uid del socket y los bytes del DNS de un mensaje NFLOG.
///
/// Un mensaje NFLOG es `nlmsghdr`(16) + `nfgenmsg`(4) + una tira de atributos TLV
/// (`nlattr`: `len`+`tipo` de 2 bytes cada uno, valor, alineado a 4). Interesan
/// dos: `NFULA_UID` (el uid del socket local, en orden de red) y `NFULA_PAYLOAD`
/// (el paquete desde la capa de red). Separado del socket para poder probar esta
/// aritmética sin privilegios, igual que `evento_de` en `procesos.rs`.
///
/// `None` si falta el payload o si está malformado; nunca lee de más.
fn dns_de_nflog(msg: &[u8]) -> Option<(Option<u32>, &[u8])> {
    const CABECERA: usize = 16 + 4; // nlmsghdr + nfgenmsg
    if msg.len() < CABECERA {
        return None;
    }
    let mut uid = None;
    let mut payload: Option<&[u8]> = None;
    let mut pos = CABECERA;
    while pos + 4 <= msg.len() {
        let nla_len = u16::from_ne_bytes([msg[pos], msg[pos + 1]]) as usize;
        // Los dos bits altos del tipo son banderas (nested / byteorder); se enmascaran.
        let nla_type = u16::from_ne_bytes([msg[pos + 2], msg[pos + 3]]) & 0x3FFF;
        if nla_len < 4 || pos + nla_len > msg.len() {
            break;
        }
        let valor = &msg[pos + 4..pos + nla_len];
        match nla_type {
            NFULA_UID if valor.len() >= 4 => {
                uid = Some(u32::from_be_bytes([valor[0], valor[1], valor[2], valor[3]]));
            }
            NFULA_PAYLOAD => payload = Some(valor),
            _ => {}
        }
        pos = (pos + nla_len).next_multiple_of(4);
    }
    let dns = dns_de_l3(payload?)?;
    Some((uid, dns))
}

/// Destripa un paquete desde la capa de red (lo que trae `NFULA_PAYLOAD`) hasta
/// los bytes del DNS: salta el encabezado IP y el UDP.
///
/// `None` si no es IPv4/IPv6 sobre UDP o si está truncado. shortcut: sólo UDP, y
/// en IPv6 sin encabezados de extensión —DNS casi siempre es UDP sin ellos—; un
/// resolvedor que use TCP por defecto pediría manejar el prefijo de largo de 2
/// bytes y el encabezado TCP.
fn dns_de_l3(l3: &[u8]) -> Option<&[u8]> {
    let version = l3.first()? >> 4;
    let (proto, l4_ini) = match version {
        4 => {
            let ihl = (l3[0] & 0x0F) as usize * 4;
            if ihl < 20 {
                return None;
            }
            (*l3.get(9)?, ihl)
        }
        6 => (*l3.get(6)?, 40usize),
        _ => return None,
    };
    if proto != IPPROTO_UDP {
        return None;
    }
    let udp = l3.get(l4_ini..)?;
    if udp.len() < 8 {
        return None;
    }
    // Tras los 8 bytes del encabezado UDP viene el DNS. El puerto no se re-chequea:
    // la regla ya filtró el 53, y `parsear_respuesta` descarta lo que no sea una
    // respuesta con A/AAAA (una consulta trae ANCOUNT=0).
    l3.get(l4_ini + 8..)
}

/// Un mensaje de configuración del grupo NFLOG: `nlmsghdr` + `nfgenmsg` + un
/// atributo. El `res_id` del `nfgenmsg` lleva el grupo en orden de red.
fn mensaje_config(grupo: u16, tipo_attr: u16, valor: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    // nlmsghdr; el largo se rellena al final.
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG).to_ne_bytes());
    m.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes()); // seq
    m.extend_from_slice(&0u32.to_ne_bytes()); // pid
                                              // nfgenmsg
    m.push(0); // nfgen_family = AF_UNSPEC
    m.push(0); // version
    m.extend_from_slice(&grupo.to_be_bytes()); // res_id (orden de red)
                                               // nlattr
    let nla_len = 4 + valor.len();
    m.extend_from_slice(&(nla_len as u16).to_ne_bytes());
    m.extend_from_slice(&tipo_attr.to_ne_bytes());
    m.extend_from_slice(valor);
    while !m.len().is_multiple_of(4) {
        m.push(0);
    }
    let len = m.len() as u32;
    m[0..4].copy_from_slice(&len.to_ne_bytes());
    m
}

/// Instala la regla y lee las respuestas DNS por NFLOG para siempre, poblando el
/// modelo. Se lanza en un hilo propio (bloqueante, como el conector de
/// `procesos.rs`). Degrada ruidoso: si la regla no se instala o el socket no abre,
/// se registra y se sale —el mapa en vivo sigue, sin dominios—.
pub fn escuchar(modelo: ModeloDnsCompartido) {
    if !instalar_regla() {
        return;
    }

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_NETFILTER,
        )
    };
    if fd < 0 {
        tracing::warn!(
            "No se pudo abrir el socket NFLOG para el snoop de DNS ({}); \
             el mapa en vivo no va a mostrar dominios",
            std::io::Error::last_os_error()
        );
        return;
    }

    let mut direccion: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    direccion.nl_family = libc::AF_NETLINK as u16;
    let enlazado = unsafe {
        libc::bind(
            fd,
            &direccion as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if enlazado < 0 {
        tracing::warn!(
            "No se pudo enlazar el socket NFLOG ({})",
            std::io::Error::last_os_error()
        );
        unsafe { libc::close(fd) };
        return;
    }

    // Ligar el grupo y pedir que copie el paquete entero.
    let bind = mensaje_config(GRUPO_NFLOG, NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND]);
    let mut modo_val = Vec::with_capacity(6);
    modo_val.extend_from_slice(&0xffff_u32.to_be_bytes()); // copy_range
    modo_val.push(NFULNL_COPY_PACKET); // copy_mode
    modo_val.push(0); // _pad
    let modo = mensaje_config(GRUPO_NFLOG, NFULA_CFG_MODE, &modo_val);
    for mensaje in [bind, modo] {
        let enviado = unsafe {
            libc::send(
                fd,
                mensaje.as_ptr() as *const libc::c_void,
                mensaje.len(),
                0,
            )
        };
        if enviado < 0 {
            tracing::warn!(
                "No se pudo configurar el grupo NFLOG ({})",
                std::io::Error::last_os_error()
            );
            unsafe { libc::close(fd) };
            return;
        }
    }

    tracing::info!("Snoop de DNS activo (NFLOG grupo {GRUPO_NFLOG})");
    // Los paquetes NFLOG pueden traer el datagrama entero (copy_range 0xffff).
    let mut buffer = vec![0u8; 65536];
    loop {
        // `recvmsg` para quedarse con el remitente: igual que el conector, un
        // socket netlink también recibe de otros procesos del usuario, así que se
        // descarta todo lo que no venga del kernel (`nl_pid == 0`).
        let mut remitente: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        };
        let mut cabecera: libc::msghdr = unsafe { std::mem::zeroed() };
        cabecera.msg_name = &mut remitente as *mut _ as *mut libc::c_void;
        cabecera.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        cabecera.msg_iov = &mut iov;
        cabecera.msg_iovlen = 1;

        let leidos = unsafe { libc::recvmsg(fd, &mut cabecera, 0) };
        if leidos > 0 {
            if cabecera.msg_flags & libc::MSG_TRUNC != 0 {
                continue; // truncado: no se procesa a medias
            }
            if remitente.nl_pid != 0 {
                continue; // no vino del kernel
            }
            procesar_tanda(&buffer[..leidos as usize], &modelo, ahora_epoch());
            continue;
        }
        if leidos < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        tracing::warn!("El socket NFLOG se cerró; el mapa en vivo deja de mostrar dominios");
        unsafe { libc::close(fd) };
        return;
    }
}

/// Recorre los mensajes netlink de una lectura y vuelca al modelo las respuestas
/// DNS de los que son paquetes NFLOG. Separado para no repetir la aritmética de
/// `nlmsg_len` y para poder probar el volcado sin socket.
fn procesar_tanda(buffer: &[u8], modelo: &ModeloDnsCompartido, ahora: u64) {
    let mut off = 0;
    while off + 16 <= buffer.len() {
        let len = u32::from_ne_bytes([
            buffer[off],
            buffer[off + 1],
            buffer[off + 2],
            buffer[off + 3],
        ]) as usize;
        if len < 16 || off + len > buffer.len() {
            break;
        }
        let tipo = u16::from_ne_bytes([buffer[off + 4], buffer[off + 5]]);
        if (tipo >> 8) == NFNL_SUBSYS_ULOG && (tipo & 0xFF) == NFULNL_MSG_PACKET {
            volcar_mensaje(&buffer[off..off + len], modelo, ahora);
        }
        off += (len + 3) & !3; // NLMSG_ALIGN
    }
}

/// Destripa un mensaje NFLOG, parsea su respuesta DNS y la anota en el modelo,
/// atribuida al uid del socket. Se descarta lo que no se pueda atribuir a un uid
/// local: sin él no hay clave `(uid, IP)` que una app vaya a consultar.
fn volcar_mensaje(nlmsg: &[u8], modelo: &ModeloDnsCompartido, ahora: u64) {
    let Some((Some(uid), dns)) = dns_de_nflog(nlmsg) else {
        return;
    };
    let Some(respuesta) = parsear_respuesta(dns) else {
        return;
    };
    if let Ok(mut m) = modelo.lock() {
        m.observar(uid, &respuesta, ahora);
    }
}

fn ahora_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arma un nombre DNS codificado (etiquetas `len`+bytes terminadas en 0).
    fn nombre(partes: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for parte in partes {
            v.push(parte.len() as u8);
            v.extend_from_slice(parte.as_bytes());
        }
        v.push(0);
        v
    }

    /// Arma una respuesta DNS: una pregunta por `dominio` y un registro A o AAAA
    /// por cada `(tipo, rdata)`. Suficiente para ejercitar el parser con paquetes
    /// con la forma real sin depender de la red.
    fn respuesta(dominio: &[&str], registros: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        m.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: respuesta
        m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        m.extend_from_slice(&(registros.len() as u16).to_be_bytes()); // ANCOUNT
        m.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        m.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        m.extend_from_slice(&nombre(dominio)); // QNAME
        m.extend_from_slice(&TIPO_A.to_be_bytes()); // QTYPE
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        for (tipo, ttl, rdata) in registros {
            // El NAME del registro, por compresión, apunta al QNAME (offset 12).
            m.extend_from_slice(&[0xC0, ENCABEZADO_DNS as u8]);
            m.extend_from_slice(&tipo.to_be_bytes());
            m.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn parsea_un_registro_a() {
        let m = respuesta(
            &["www", "example", "com"],
            &[(TIPO_A, 300, vec![93, 184, 216, 34])],
        );
        let r = parsear_respuesta(&m).expect("parsea");
        assert_eq!(r.dominio, "www.example.com");
        assert_eq!(
            r.registros,
            vec![RegistroDns {
                ip: "93.184.216.34".into(),
                ttl: 300
            }]
        );
    }

    #[test]
    fn parsea_un_registro_aaaa() {
        // 2606:2800:220:1:248:1893:25c8:1946
        let v6 = vec![
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8,
            0x19, 0x46,
        ];
        let m = respuesta(&["example", "com"], &[(TIPO_AAAA, 60, v6)]);
        let r = parsear_respuesta(&m).expect("parsea");
        assert_eq!(r.dominio, "example.com");
        assert_eq!(r.registros.len(), 1);
        assert_eq!(r.registros[0].ip, "2606:2800:220:1:248:1893:25c8:1946");
        assert_eq!(r.registros[0].ttl, 60);
    }

    /// Varias A en una respuesta —lo normal para un sitio con balanceo— se mapean
    /// todas al mismo nombre consultado.
    #[test]
    fn varias_ips_al_mismo_nombre() {
        let m = respuesta(
            &["cdn", "sitio", "net"],
            &[
                (TIPO_A, 120, vec![203, 0, 113, 1]),
                (TIPO_A, 120, vec![203, 0, 113, 2]),
                (
                    TIPO_AAAA,
                    120,
                    vec![0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
            ],
        );
        let r = parsear_respuesta(&m).expect("parsea");
        assert_eq!(r.registros.len(), 3);
        assert_eq!(r.registros[0].ip, "203.0.113.1");
        assert_eq!(r.registros[1].ip, "203.0.113.2");
        assert_eq!(r.registros[2].ip, "2001:db8::1");
    }

    /// Los registros que no son A/AAAA (un CNAME, por ejemplo) se saltan sin
    /// romper, y se avanza por su RDLENGTH para llegar a los que sí interesan.
    #[test]
    fn un_cname_se_saltea_y_se_siguen_los_a() {
        let cname_rdata = nombre(&["sitio", "cdn", "net"]);
        let m = respuesta(
            &["www", "sitio", "com"],
            &[
                (5, 300, cname_rdata), // CNAME
                (TIPO_A, 300, vec![198, 51, 100, 7]),
            ],
        );
        let r = parsear_respuesta(&m).expect("parsea");
        assert_eq!(r.dominio, "www.sitio.com");
        assert_eq!(
            r.registros,
            vec![RegistroDns {
                ip: "198.51.100.7".into(),
                ttl: 300
            }]
        );
    }

    /// Una respuesta sin ningún A/AAAA (sólo un CNAME, o NXDOMAIN) no mapea nada.
    #[test]
    fn una_respuesta_sin_direcciones_es_none() {
        let m = respuesta(&["nada", "com"], &[(5, 300, nombre(&["otro", "com"]))]);
        assert_eq!(parsear_respuesta(&m), None);
        // Y una respuesta con ANCOUNT=0.
        let m0 = respuesta(&["nada", "com"], &[]);
        assert_eq!(parsear_respuesta(&m0), None);
    }

    /// Un paquete malformado/truncado en cualquier punto devuelve `None` y no
    /// entra en pánico ni lee de más: es lo que llega por un socket, basura
    /// incluida.
    #[test]
    fn un_paquete_truncado_no_rompe() {
        assert_eq!(parsear_respuesta(&[]), None);
        assert_eq!(parsear_respuesta(&[0u8; 11]), None); // más corto que el encabezado

        let completo = respuesta(&["example", "com"], &[(TIPO_A, 300, vec![1, 2, 3, 4])]);
        // Cortado en cada largo posible: ninguno debe romper.
        for corte in 0..completo.len() {
            let _ = parsear_respuesta(&completo[..corte]);
        }
        // Un RDLENGTH que miente (dice 16 bytes de A pero no están) no lee de más.
        let mut mentiroso = respuesta(&["x", "y"], &[(TIPO_A, 300, vec![1, 2, 3, 4])]);
        let n = mentiroso.len();
        mentiroso[n - 5] = 0xff; // RDLENGTH enorme
        assert_eq!(parsear_respuesta(&mentiroso), None);
    }

    /// Un puntero de compresión que apunta a sí mismo no cuelga: el tope de saltos
    /// lo corta y devuelve `None`.
    #[test]
    fn un_puntero_en_bucle_no_cuelga() {
        let mut m = vec![0u8; ENCABEZADO_DNS];
        m[5] = 1; // QDCOUNT=1
                  // Un puntero en 12 que apunta a 12: bucle infinito sin el tope.
        m.push(0xC0);
        m.push(ENCABEZADO_DNS as u8);
        assert_eq!(parsear_respuesta(&m), None);
    }

    // ── El modelo acotado y el TTL ────────────────────────────────────────────

    fn resp(dominio: &str, ip: &str, ttl: u32) -> RespuestaDns {
        RespuestaDns {
            dominio: dominio.into(),
            registros: vec![RegistroDns { ip: ip.into(), ttl }],
        }
    }

    /// Lo observado se puede consultar por `(uid, IP)` mientras no venza.
    #[test]
    fn observar_y_consultar_por_uid_e_ip() {
        let mut m = ModeloDns::nuevo();
        m.observar(1000, &resp("example.com", "93.184.216.34", 300), 100);
        assert_eq!(
            m.dominio_de(1000, "93.184.216.34", 200),
            Some("example.com".into())
        );
        // Otro uid no ve la entrada: el mismo destino desde otra sesión no se funde.
        assert_eq!(m.dominio_de(1001, "93.184.216.34", 200), None);
        // Una IP que nunca se resolvió para ese uid tampoco.
        assert_eq!(m.dominio_de(1000, "198.51.100.1", 200), None);
    }

    /// Una entrada vencida no se usa: pasado su TTL, `dominio_de` devuelve `None`
    /// —la IP pudo reasignarse a otro dominio—.
    #[test]
    fn una_entrada_vencida_no_se_usa() {
        let mut m = ModeloDns::nuevo();
        m.observar(1000, &resp("example.com", "93.184.216.34", 300), 100);
        // Vence en 100 + 300 = 400. Justo antes vale, justo después no.
        assert!(m.dominio_de(1000, "93.184.216.34", 399).is_some());
        assert_eq!(m.dominio_de(1000, "93.184.216.34", 400), None);
        assert_eq!(m.dominio_de(1000, "93.184.216.34", 100_000), None);
    }

    /// Un TTL de 0 (o muy bajo) se eleva al piso: la conexión que sigue a la
    /// consulta todavía encuentra el dominio ese ratito.
    #[test]
    fn el_ttl_tiene_un_piso_para_que_el_cero_sirva() {
        let mut m = ModeloDns::nuevo();
        m.observar(1000, &resp("efimero.com", "203.0.113.9", 0), 100);
        assert_eq!(
            m.dominio_de(1000, "203.0.113.9", 100 + TTL_PISO - 1),
            Some("efimero.com".into())
        );
        assert_eq!(m.dominio_de(1000, "203.0.113.9", 100 + TTL_PISO), None);
    }

    /// Un TTL enorme se recorta al techo: una IP no queda clavada a un dominio
    /// viejo por días.
    #[test]
    fn el_ttl_tiene_un_techo() {
        let mut m = ModeloDns::nuevo();
        m.observar(1000, &resp("largo.com", "203.0.113.10", u32::MAX), 100);
        assert!(m
            .dominio_de(1000, "203.0.113.10", 100 + TTL_TECHO - 1)
            .is_some());
        assert_eq!(
            m.dominio_de(1000, "203.0.113.10", 100 + TTL_TECHO + 1),
            None
        );
    }

    /// La IP que se reasigna a otro dominio toma el último visto: gana la
    /// resolución más reciente, que es la que la app va a usar.
    #[test]
    fn la_ip_reasignada_toma_el_ultimo_dominio() {
        let mut m = ModeloDns::nuevo();
        m.observar(1000, &resp("viejo.com", "203.0.113.5", 300), 100);
        m.observar(1000, &resp("nuevo.com", "203.0.113.5", 300), 150);
        assert_eq!(
            m.dominio_de(1000, "203.0.113.5", 200),
            Some("nuevo.com".into())
        );
    }

    /// Al pasar el techo se desaloja la entrada que vence antes —no una
    /// cualquiera— y el modelo no crece sin fin.
    #[test]
    fn al_pasar_el_techo_se_desaloja_la_que_vence_antes() {
        let mut m = ModeloDns::nuevo();
        // La primera vence mucho antes que el resto (TTL al piso vs. al techo).
        m.observar(1, &resp("corta.com", "10.0.0.1", 0), 0);
        for i in 0..MAXIMO {
            let ip = format!("10.1.{}.{}", i / 256, i % 256);
            m.observar(1, &resp("larga.com", &ip, u32::MAX), 0);
        }
        // Se pasó el techo al menos una vez: la entrada más corta tuvo que caer.
        assert_eq!(
            m.dominio_de(1, "10.0.0.1", 1),
            None,
            "la que vence antes se desalojó"
        );
        // Y una de las largas sigue.
        assert_eq!(m.dominio_de(1, "10.1.0.0", 1), Some("larga.com".into()));
    }

    // ── Pruebas de QA: bordes del parser, techo y garantías de solo-observar ───

    /// Un truncado en CUALQUIER punto de una respuesta con un único registro la
    /// invalida entera: no se devuelve un registro a medias.
    #[test]
    fn todo_truncado_de_una_respuesta_valida_da_none() {
        let completo = respuesta(&["example", "com"], &[(TIPO_A, 300, vec![1, 2, 3, 4])]);
        for corte in 0..completo.len() {
            assert_eq!(parsear_respuesta(&completo[..corte]), None, "corte {corte}");
        }
        assert!(parsear_respuesta(&completo).is_some());
    }

    /// Dos punteros que se apuntan entre sí (A → B → A) en el NAME de un registro
    /// no cuelgan ni rompen: el parser termina y descarta el mensaje.
    #[test]
    fn punteros_de_compresion_en_ciclo_de_dos_no_cuelgan() {
        let mut m = respuesta(&["example", "com"], &[(TIPO_A, 300, vec![1, 2, 3, 4])]);
        // El NAME del registro empieza tras el QNAME: 12 + (1+7+1+3+1) + 4 = 29.
        let ini = 29;
        assert_eq!(&m[ini..ini + 2], &[0xC0, ENCABEZADO_DNS as u8]);
        // Se agregan al final dos punteros cruzados y el NAME apunta al primero.
        let a = m.len();
        m.extend_from_slice(&[0xC0, (a + 2) as u8]);
        m.extend_from_slice(&[0xC0, a as u8]);
        m[ini + 1] = a as u8;
        assert_eq!(parsear_respuesta(&m), None);
    }

    /// Un registro A con RDLENGTH distinto de 4 (o AAAA distinto de 16) no se
    /// interpreta como dirección: no se inventa una IP de bytes ajenos.
    #[test]
    fn un_rdlength_inconsistente_con_el_tipo_no_da_ip() {
        let a_corta = respuesta(&["x", "com"], &[(TIPO_A, 300, vec![1, 2, 3])]);
        assert_eq!(parsear_respuesta(&a_corta), None);
        let a_larga = respuesta(&["x", "com"], &[(TIPO_A, 300, vec![1, 2, 3, 4, 5])]);
        assert_eq!(parsear_respuesta(&a_larga), None);
        let aaaa_corta = respuesta(&["x", "com"], &[(TIPO_AAAA, 300, vec![0; 4])]);
        assert_eq!(parsear_respuesta(&aaaa_corta), None);
    }

    /// El modelo nunca pasa el techo, por muchas IPs distintas que se observen.
    #[test]
    fn el_modelo_nunca_pasa_el_techo() {
        let mut m = ModeloDns::nuevo();
        for i in 0..(MAXIMO + 50) {
            let ip = format!("10.2.{}.{}", i / 256, i % 256);
            m.observar(1, &resp("a.com", &ip, 300), i as u64);
        }
        assert_eq!(m.registros.len(), MAXIMO);
    }

    /// Refrescar una clave que ya está, con el modelo lleno, NO desaloja a otra:
    /// solo una clave nueva hace lugar.
    #[test]
    fn refrescar_una_clave_existente_con_el_modelo_lleno_no_desaloja() {
        let mut m = ModeloDns::nuevo();
        for i in 0..MAXIMO {
            let ip = format!("10.3.{}.{}", i / 256, i % 256);
            m.observar(1, &resp("a.com", &ip, 300), 0);
        }
        m.observar(1, &resp("b.com", "10.3.0.0", 300), 10);
        assert_eq!(m.registros.len(), MAXIMO);
        assert_eq!(m.dominio_de(1, "10.3.0.0", 11), Some("b.com".into()));
        assert_eq!(m.dominio_de(1, "10.3.0.1", 11), Some("a.com".into()));
    }

    /// El techo es por modelo, no por uid, pero el desalojo respeta la
    /// atribución: la entrada que cae no hace aparecer el dominio en otro uid.
    #[test]
    fn el_desalojo_no_cambia_a_quien_pertenece_lo_que_queda() {
        let mut m = ModeloDns::nuevo();
        m.observar(7, &resp("siete.com", "192.0.2.7", 0), 0); // vence primero
        for i in 0..MAXIMO {
            let ip = format!("10.4.{}.{}", i / 256, i % 256);
            m.observar(8, &resp("ocho.com", &ip, 3600), 0);
        }
        assert_eq!(m.dominio_de(7, "192.0.2.7", 1), None);
        assert_eq!(m.dominio_de(8, "192.0.2.7", 1), None);
        assert_eq!(m.dominio_de(8, "10.4.0.0", 1), Some("ocho.com".into()));
    }

    /// IPv4 con IHL menor a 5 (encabezado inválido) no se destripa.
    #[test]
    fn un_ihl_invalido_no_se_destripa() {
        let mut p = ipv4_udp(&[0u8; 12]);
        p[0] = 0x44; // IHL 4 → 16 bytes, menor al mínimo de 20
        assert_eq!(dns_de_l3(&p), None);
    }

    /// Un atributo con `nla_len` que miente (menor a 4 o más allá del mensaje)
    /// corta la lectura sin leer de más ni romper.
    #[test]
    fn un_atributo_nflog_con_largo_mentiroso_no_rompe() {
        for mentira in [0u16, 3, 9999] {
            let mut m = vec![0u8; 16 + 4];
            m.extend_from_slice(&mentira.to_ne_bytes());
            m.extend_from_slice(&NFULA_PAYLOAD.to_ne_bytes());
            m.extend_from_slice(&[0u8; 8]);
            assert_eq!(dns_de_nflog(&m), None, "nla_len {mentira}");
        }
    }

    /// Una tanda con dos mensajes de uids distintos atribuye cada IP a su uid; uno
    /// con otro tipo de mensaje o con largo mentiroso se ignora sin romper.
    #[test]
    fn una_tanda_atribuye_por_uid_e_ignora_lo_ajeno() {
        let modelo = modelo_dns_nuevo();
        let d1 = respuesta(&["uno", "com"], &[(TIPO_A, 300, vec![192, 0, 2, 1])]);
        let d2 = respuesta(&["dos", "com"], &[(TIPO_A, 300, vec![192, 0, 2, 1])]);
        let d3 = respuesta(&["tres", "com"], &[(TIPO_A, 300, vec![192, 0, 2, 3])]);
        let mut ajeno = nflog(Some(1000), &ipv4_udp(&d3));
        ajeno[4..6].copy_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG).to_ne_bytes());

        let mut tanda = nflog(Some(1000), &ipv4_udp(&d1));
        tanda.extend(nflog(Some(1001), &ipv4_udp(&d2)));
        tanda.extend(ajeno);
        // Un encabezado final con largo que se sale del buffer: corta sin romper.
        let mut roto = vec![0u8; 16];
        roto[0..4].copy_from_slice(&9999u32.to_ne_bytes());
        tanda.extend(roto);
        procesar_tanda(&tanda, &modelo, 100);

        let m = modelo.lock().unwrap();
        assert_eq!(m.dominio_de(1000, "192.0.2.1", 101), Some("uno.com".into()));
        assert_eq!(m.dominio_de(1001, "192.0.2.1", 101), Some("dos.com".into()));
        assert_eq!(
            m.dominio_de(1000, "192.0.2.3", 101),
            None,
            "tipo ajeno ignorado"
        );
    }

    /// Solo observa: el código de producción del snoop no abre ningún socket
    /// AF_INET/AF_INET6 (ni TCP ni UDP de std) y su único `socket()` es netlink.
    /// Se verifica sobre la fuente: ejercer NFLOG real pide root.
    #[test]
    fn el_snoop_no_abre_sockets_inet() {
        let fuente = include_str!("dns.rs");
        let (produccion, _) = fuente
            .split_once("#[cfg(test)]")
            .expect("hay módulo de pruebas");
        // Sin comentarios: el módulo explica en prosa que no abre AF_INET.
        let produccion: String = produccion
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for prohibido in [
            "AF_INET",
            "UdpSocket",
            "TcpStream",
            "TcpListener",
            "SOCK_DGRAM",
        ] {
            assert!(
                !produccion.contains(prohibido),
                "el snoop no debe usar {prohibido}"
            );
        }
        assert_eq!(produccion.matches("libc::socket(").count(), 1);
        assert!(produccion.contains("libc::AF_NETLINK"));
    }

    // ── El destripado NFLOG → IP/UDP → DNS ────────────────────────────────────

    /// Envuelve `dns` en un datagrama UDP sobre IPv4 (sport 53), como lo trae
    /// `NFULA_PAYLOAD`. El encabezado IP es mínimo (IHL=5) y sólo lleva lo que el
    /// destripado mira: versión, IHL y el protocolo.
    fn ipv4_udp(dns: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20]; // encabezado IPv4 de 20 bytes
        p[0] = 0x45; // versión 4, IHL 5
        p[9] = IPPROTO_UDP;
        // UDP: sport 53, dport efímero, largo, checksum 0.
        p.extend_from_slice(&PUERTO_DNS.to_be_bytes());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(dns);
        p
    }

    /// Envuelve un payload L3 en un mensaje NFLOG completo: `nlmsghdr`+`nfgenmsg`
    /// y los atributos `NFULA_UID` (si `uid`) y `NFULA_PAYLOAD`.
    fn nflog(uid: Option<u32>, l3: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; 16 + 4]; // nlmsghdr + nfgenmsg, no leídos por el parser
        if let Some(uid) = uid {
            // NFULA_UID: be32, nla_len = 8.
            m.extend_from_slice(&8u16.to_ne_bytes());
            m.extend_from_slice(&NFULA_UID.to_ne_bytes());
            m.extend_from_slice(&uid.to_be_bytes());
        }
        // NFULA_PAYLOAD.
        let nla_len = 4 + l3.len();
        m.extend_from_slice(&(nla_len as u16).to_ne_bytes());
        m.extend_from_slice(&NFULA_PAYLOAD.to_ne_bytes());
        m.extend_from_slice(l3);
        while !m.len().is_multiple_of(4) {
            m.push(0);
        }
        // Completa el `nlmsghdr` para que `procesar_tanda` reconozca el mensaje:
        // el largo total y el tipo «paquete» del subsistema del log.
        let len = m.len() as u32;
        m[0..4].copy_from_slice(&len.to_ne_bytes());
        m[4..6].copy_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET).to_ne_bytes());
        m
    }

    #[test]
    fn destripa_el_uid_y_el_dns_de_un_mensaje_nflog() {
        let dns = respuesta(
            &["example", "com"],
            &[(TIPO_A, 300, vec![93, 184, 216, 34])],
        );
        let msg = nflog(Some(1000), &ipv4_udp(&dns));
        let (uid, bytes) = dns_de_nflog(&msg).expect("destripa");
        assert_eq!(uid, Some(1000));
        let r = parsear_respuesta(bytes).expect("parsea el DNS extraído");
        assert_eq!(r.dominio, "example.com");
        assert_eq!(r.registros[0].ip, "93.184.216.34");
    }

    /// Sin `NFULA_UID` (un paquete que el kernel no pudo atribuir a un socket) se
    /// devuelve el DNS con uid `None`: `volcar_mensaje` después lo descarta.
    #[test]
    fn un_mensaje_sin_uid_da_none_de_uid() {
        let dns = respuesta(&["x", "y"], &[(TIPO_A, 60, vec![1, 2, 3, 4])]);
        let (uid, _) = dns_de_nflog(&nflog(None, &ipv4_udp(&dns))).expect("destripa");
        assert_eq!(uid, None);
    }

    /// Un L3 que no es UDP, o truncado, no da DNS. Y un mensaje NFLOG sin payload
    /// tampoco.
    #[test]
    fn nflog_malformado_no_rompe() {
        // IPv4 con protocolo TCP (6): no se destripa.
        let mut tcp = ipv4_udp(&[0u8; 12]);
        tcp[9] = 6;
        assert_eq!(dns_de_l3(&tcp), None);
        // Un L3 vacío o demasiado corto.
        assert_eq!(dns_de_l3(&[]), None);
        assert_eq!(dns_de_l3(&[0x45]), None);
        // Un NFLOG sin atributo de payload.
        let mut sin_payload = vec![0u8; 16 + 4];
        sin_payload.extend_from_slice(&8u16.to_ne_bytes());
        sin_payload.extend_from_slice(&NFULA_UID.to_ne_bytes());
        sin_payload.extend_from_slice(&7u32.to_be_bytes());
        assert_eq!(dns_de_nflog(&sin_payload), None);
        // Un NFLOG más corto que sus cabeceras.
        assert_eq!(dns_de_nflog(&[0u8; 8]), None);
    }

    /// IPv6/UDP también se destripa: el encabezado fijo son 40 bytes y el next
    /// header a los 6.
    #[test]
    fn destripa_ipv6_udp() {
        let dns = respuesta(&["v6", "com"], &[(TIPO_AAAA, 60, vec![0; 16])]);
        let mut p = vec![0u8; 40];
        p[0] = 0x60; // versión 6
        p[6] = IPPROTO_UDP; // next header
        p.extend_from_slice(&PUERTO_DNS.to_be_bytes());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&dns);
        let bytes = dns_de_l3(&p).expect("destripa v6");
        assert_eq!(parsear_respuesta(bytes).unwrap().dominio, "v6.com");
    }

    /// El camino entero del lector, sin el socket: una tanda con un mensaje NFLOG
    /// de una respuesta DNS deja el dominio en el modelo, atribuido al uid, y
    /// consultable por `(uid, IP)` como lo hará el enriquecimiento del mapa.
    #[test]
    fn una_tanda_nflog_puebla_el_modelo_y_se_consulta_por_uid_e_ip() {
        let modelo = modelo_dns_nuevo();
        let dns = respuesta(
            &["www", "example", "com"],
            &[(TIPO_A, 300, vec![93, 184, 216, 34])],
        );
        procesar_tanda(&nflog(Some(1000), &ipv4_udp(&dns)), &modelo, 100);

        let dominio = modelo
            .lock()
            .unwrap()
            .dominio_de(1000, "93.184.216.34", 200);
        assert_eq!(dominio, Some("www.example.com".into()));
        // Otro uid no hereda la atribución.
        assert_eq!(
            modelo
                .lock()
                .unwrap()
                .dominio_de(1001, "93.184.216.34", 200),
            None
        );
    }

    /// Una respuesta sin uid no entra al modelo: no se puede atribuir a una app.
    #[test]
    fn una_respuesta_sin_uid_no_entra_al_modelo() {
        let modelo = modelo_dns_nuevo();
        let dns = respuesta(&["x", "com"], &[(TIPO_A, 300, vec![1, 2, 3, 4])]);
        procesar_tanda(&nflog(None, &ipv4_udp(&dns)), &modelo, 100);
        assert_eq!(modelo.lock().unwrap().dominio_de(0, "1.2.3.4", 101), None);
    }

    /// La regla sólo registra las respuestas DNS (sport 53) al grupo pedido, y
    /// nunca descarta: no hay `drop` ni cambio de política, el veredicto queda
    /// idéntico. Es idempotente (`destroy` antes de `table`).
    #[test]
    fn la_regla_solo_registra_y_no_bloquea() {
        let r = regla_nft(GRUPO_NFLOG);
        assert!(r.contains(&format!("log group {GRUPO_NFLOG}")));
        assert!(r.contains("sport 53"));
        assert!(r.contains(&format!("destroy table inet {TABLA_NFT}")));
        assert!(
            !r.contains("drop") && !r.contains("reject"),
            "la regla del snoop no debe bloquear nada: {r}"
        );
    }

    /// El mensaje de bind al grupo tiene la forma que el kernel espera: el largo
    /// coincide con el buffer, el tipo es CONFIG del subsistema del log, el grupo
    /// va en orden de red en el `res_id`, y el atributo lleva el comando BIND.
    #[test]
    fn el_mensaje_de_bind_tiene_la_forma_esperada() {
        let m = mensaje_config(GRUPO_NFLOG, NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND]);
        assert_eq!(
            u32::from_ne_bytes(m[0..4].try_into().unwrap()),
            m.len() as u32
        );
        assert_eq!(
            u16::from_ne_bytes(m[4..6].try_into().unwrap()),
            (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG
        );
        // res_id = grupo en orden de red, tras el nlmsghdr (16) + family/version (2).
        assert_eq!(u16::from_be_bytes([m[18], m[19]]), GRUPO_NFLOG);
        // El atributo: nla_len=5, tipo CFG_CMD, valor BIND.
        assert_eq!(u16::from_ne_bytes([m[20], m[21]]), 5);
        assert_eq!(u16::from_ne_bytes([m[22], m[23]]), NFULA_CFG_CMD);
        assert_eq!(m[24], NFULNL_CFG_CMD_BIND);
    }

    /// El mensaje de modo pide copiar el paquete entero. Su atributo mide 10
    /// bytes (4 de cabecera + 6 de valor) y el mensaje queda alineado a 4: ejercita
    /// el relleno del atributo.
    #[test]
    fn el_mensaje_de_modo_pide_copiar_el_paquete_entero() {
        let mut valor = Vec::with_capacity(6);
        valor.extend_from_slice(&0xffff_u32.to_be_bytes()); // copy_range
        valor.push(NFULNL_COPY_PACKET); // copy_mode
        valor.push(0); // _pad
        let m = mensaje_config(GRUPO_NFLOG, NFULA_CFG_MODE, &valor);
        // Largo del nlmsghdr coherente y alineado a 4.
        assert_eq!(
            u32::from_ne_bytes(m[0..4].try_into().unwrap()),
            m.len() as u32
        );
        assert!(m.len().is_multiple_of(4), "el mensaje queda alineado");
        // nla_len=10, tipo MODE, copy_mode = COPY_PACKET en el 5º byte del valor.
        assert_eq!(u16::from_ne_bytes([m[20], m[21]]), 10);
        assert_eq!(u16::from_ne_bytes([m[22], m[23]]), NFULA_CFG_MODE);
        assert_eq!(m[28], NFULNL_COPY_PACKET);
    }
}
