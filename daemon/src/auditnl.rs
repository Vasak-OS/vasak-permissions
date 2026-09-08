//! Leer las denegaciones del socket de auditoría, y no del registro del kernel.
//!
//! # Por qué
//!
//! El vigilante leía `/dev/kmsg`, que es la salida de `printk`, y ahí los
//! registros de auditoría vienen con cupo: cinco mensajes por intervalo con
//! ráfaga de diez. Lo que sobra el kernel lo tira y lo anuncia como
//! `kauditd_printk_skb: N callbacks suppressed`.
//!
//! Medido en un escritorio, dos horas y cuarto de sesión normal: **42410
//! registros descartados contra 1672 que pasaron**, el 96% perdido. Y de los
//! que pasaban, 1598 eran el ruido de los perfiles del sistema en modo aviso y
//! **uno solo** una denegación de verdad. Una denegación descartada no genera
//! aviso, y sin aviso nadie recibe la oferta de desbloquear.
//!
//! El kernel manda los mismos registros por un grupo multicast de netlink que
//! no pasa por `printk` ni por su cupo. Eso es lo que se lee acá.
//!
//! # Por qué multicast y no tomar la cola
//!
//! Hay dos formas de recibir auditoría. Una es registrarse como **el** demonio
//! de auditoría (`AUDIT_SET` con el pid propio), que es lo que hace `auditd`;
//! sólo puede haber uno, así que hacerlo le sacaría los registros a quien ya
//! los estuviera leyendo. La otra es el grupo multicast de sólo lectura
//! —`AUDIT_NLGRP_READLOG`, que existe desde Linux 3.16 y es el que usa
//! `systemd-journald`—, donde caben varios lectores a la vez y nadie le quita
//! nada a nadie. Es la que corresponde: nosotros queremos mirar, no gobernar.
//!
//! Necesita `CAP_AUDIT_READ`. El servicio corre como root, así que la tiene; si
//! algún día se le recortan las capacidades, ésta tiene que quedar.
//!
//! # Los dos a la vez
//!
//! Esto no reemplaza al lector de `/dev/kmsg`: corren los dos y las
//! denegaciones repetidas se descartan por el número de serie que trae el
//! propio registro.
//!
//! Es a propósito, y es por lo que no se puede comprobar desde acá. Si el
//! socket se abre pero el kernel no entrega nada —una configuración que no
//! previmos, un kernel sin el grupo—, con un solo lector nos quedaríamos sin
//! ninguna denegación **y con el diario diciendo que estamos escuchando**. Con
//! los dos, el peor caso es el de antes.

/// La familia de netlink de auditoría.
const NETLINK_AUDIT: i32 = 9;

/// El grupo multicast de sólo lectura, en la forma de máscara que espera
/// `bind`: `AUDIT_NLGRP_READLOG` es 1, y los grupos se piden como `1 << (n-1)`.
const GRUPO_LECTURA: u32 = 1;

/// Debajo de esto son mensajes de control de netlink (`NLMSG_ERROR`,
/// `NLMSG_DONE`), no registros de auditoría.
const PRIMER_TIPO_DE_EVENTO: u16 = 1300;

/// El encabezado `nlmsghdr`: largo, tipo, banderas, secuencia y pid.
const CABECERA: usize = 16;

/// El texto de un registro de auditoría, si el mensaje es uno.
///
/// Separado del socket para poder comprobarlo sin privilegios ni kernel, igual
/// que el conector de procesos: es aritmética de desplazamientos, que es justo
/// donde uno se equivoca.
///
/// Lo que devuelve tiene la misma forma que la línea de `/dev/kmsg` de la parte
/// que importa —empieza en `audit(<segundos>.<milésimas>:<serie>):`— así que lo
/// lee el mismo analizador y no hay dos gramáticas que mantener sincronizadas.
pub fn texto_de_mensaje(mensaje: &[u8]) -> Option<&str> {
    if mensaje.len() < CABECERA {
        return None;
    }
    let largo = u32::from_ne_bytes(mensaje[0..4].try_into().ok()?) as usize;
    let tipo = u16::from_ne_bytes(mensaje[4..6].try_into().ok()?);
    if tipo < PRIMER_TIPO_DE_EVENTO {
        return None;
    }
    // El largo lo declara el emisor: se recorta a lo que de verdad llegó antes
    // de usarlo, o un valor inflado leería fuera del mensaje.
    if largo < CABECERA {
        return None;
    }
    let fin = largo.min(mensaje.len());
    std::str::from_utf8(&mensaje[CABECERA..fin]).ok()
}

/// Escucha el socket de auditoría y manda lo que reconoce.
///
/// Nunca termina; se lanza en un hilo propio. Si el socket no se puede abrir o
/// enlazar se registra y se sale: queda el lector de `/dev/kmsg`, que es como
/// estaba antes.
pub fn escuchar(envio: tokio::sync::mpsc::Sender<crate::audit::Denegacion>) {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        tracing::info!(
            "No se pudo abrir el socket de auditoría ({}); \
             se leen las denegaciones sólo del registro del kernel, que tiene cupo",
            std::io::Error::last_os_error()
        );
        return;
    }

    let mut direccion: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    direccion.nl_family = libc::AF_NETLINK as u16;
    direccion.nl_groups = GRUPO_LECTURA;
    let enlazado = unsafe {
        libc::bind(
            fd,
            &direccion as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if enlazado < 0 {
        // Lo más probable acá es `EPERM`: falta `CAP_AUDIT_READ`.
        tracing::info!(
            "No se pudo escuchar el registro de auditoría ({}); \
             se leen las denegaciones sólo del registro del kernel, que tiene cupo",
            std::io::Error::last_os_error()
        );
        unsafe { libc::close(fd) };
        return;
    }

    tracing::info!("Escuchando el registro de auditoría del kernel");
    // Un registro de auditoría es texto y no llega ni cerca de esto, pero el
    // margen es barato y un mensaje truncado se descarta entero.
    let mut buffer = [0u8; 8192];
    loop {
        // `recvmsg` y no `recv`, para quedarse con la dirección de quien envía.
        //
        // Un socket de netlink también recibe mensajes de **otros procesos**
        // que conozcan nuestro identificador de puerto. Sin mirar el remitente,
        // cualquiera podría fabricar una denegación y hacer que le avisemos a
        // la persona de un bloqueo que nunca ocurrió, atribuido a la aplicación
        // que él eligiera. Los mensajes del kernel llegan con `nl_pid` en cero.
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
        if leidos <= 0 {
            if leidos < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            tracing::warn!(
                "El socket de auditoría se cerró; quedan las denegaciones que pase el \
                 registro del kernel"
            );
            unsafe { libc::close(fd) };
            return;
        }
        // Truncado: no se puede confiar en lo que quedó, y analizarlo a medias
        // sería leer campos de otro mensaje.
        if cabecera.msg_flags & libc::MSG_TRUNC != 0 {
            continue;
        }
        if remitente.nl_pid != 0 {
            tracing::debug!(
                "Registro de auditoría descartado: no vino del kernel (nl_pid={})",
                remitente.nl_pid
            );
            continue;
        }

        let Some(texto) = texto_de_mensaje(&buffer[..leidos as usize]) else {
            continue;
        };
        let Some(denegacion) = crate::audit::parsear(texto) else {
            continue;
        };
        if envio.blocking_send(denegacion).is_err() {
            unsafe { libc::close(fd) };
            return; // el servicio se está cerrando
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arma un mensaje de netlink con el texto adentro.
    fn mensaje(tipo: u16, texto: &str) -> Vec<u8> {
        let largo = CABECERA + texto.len();
        let mut m = Vec::with_capacity(largo);
        m.extend_from_slice(&(largo as u32).to_ne_bytes());
        m.extend_from_slice(&tipo.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes()); // banderas
        m.extend_from_slice(&0u32.to_ne_bytes()); // secuencia
        m.extend_from_slice(&0u32.to_ne_bytes()); // pid
        m.extend_from_slice(texto.as_bytes());
        m
    }

    const UNA_DENEGACION: &str = concat!(
        "audit(1788876866.510:49055): apparmor=\"DENIED\" operation=\"open\" ",
        "class=\"file\" profile=\"vasak-appimage\" name=\"/home/pato/.ssh/id_ed25519\" ",
        "pid=232440 comm=\"cat\" requested_mask=\"r\" denied_mask=\"r\" fsuid=1000 ouid=1000"
    );

    /// Un registro de AppArmor (tipo 1400) entrega su texto.
    #[test]
    fn de_un_registro_sale_el_texto() {
        let m = mensaje(1400, UNA_DENEGACION);
        assert_eq!(texto_de_mensaje(&m), Some(UNA_DENEGACION));
    }

    /// Y ese texto lo entiende el mismo analizador que el de `/dev/kmsg`.
    ///
    /// Es la razón de que este módulo no tenga gramática propia: el registro
    /// del kernel y el socket traen la misma línea, sólo que por caminos
    /// distintos. Dos analizadores serían dos cosas que se desincronizan.
    #[test]
    fn el_texto_lo_lee_el_analizador_de_siempre() {
        let m = mensaje(1400, UNA_DENEGACION);
        let denegacion = crate::audit::parsear(texto_de_mensaje(&m).unwrap()).unwrap();
        assert_eq!(denegacion.perfil, "vasak-appimage");
        assert_eq!(denegacion.ruta, "/home/pato/.ssh/id_ed25519");
        assert_eq!(denegacion.pid, 232440);
        assert_eq!(denegacion.uid, 1000);
    }

    /// Los mensajes de control de netlink no son registros.
    #[test]
    fn los_mensajes_de_control_se_ignoran() {
        // NLMSG_ERROR y NLMSG_DONE.
        assert_eq!(texto_de_mensaje(&mensaje(2, UNA_DENEGACION)), None);
        assert_eq!(texto_de_mensaje(&mensaje(3, UNA_DENEGACION)), None);
    }

    /// Un mensaje más corto que su propio encabezado no se lee.
    #[test]
    fn un_mensaje_corto_no_lee_de_mas() {
        let m = mensaje(1400, UNA_DENEGACION);
        assert_eq!(texto_de_mensaje(&m[..CABECERA - 1]), None);
        assert_eq!(texto_de_mensaje(&[]), None);
    }

    /// Un largo declarado más grande que lo que llegó no lee fuera del buffer.
    ///
    /// El largo lo pone quien envía. Creerle sería leer memoria de otro
    /// mensaje, o de más allá del buffer.
    #[test]
    fn un_largo_inflado_no_se_cree() {
        let mut m = mensaje(1400, UNA_DENEGACION);
        let inflado = m.len() as u32 + 4096;
        m[0..4].copy_from_slice(&inflado.to_ne_bytes());
        // No entra en pánico y devuelve sólo lo que de verdad llegó.
        assert_eq!(texto_de_mensaje(&m), Some(UNA_DENEGACION));
    }

    /// Un largo por debajo del encabezado tampoco.
    #[test]
    fn un_largo_imposible_se_descarta() {
        let mut m = mensaje(1400, UNA_DENEGACION);
        m[0..4].copy_from_slice(&4u32.to_ne_bytes());
        assert_eq!(texto_de_mensaje(&m), None);
    }
}
