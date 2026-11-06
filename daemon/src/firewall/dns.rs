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
}
