//! The VasakOS permission service.
//!
//! Answers one question — "may this program use this?" — for cameras,
//! microphones, screen capture and the user's online accounts alike, and
//! remembers what the person answered.
//!
//! It runs as root on the system bus for two reasons that admit no
//! alternative: identifying a caller means reading `/proc/<pid>/exe` of a
//! process that is not ours, and the stored answers have to live somewhere the
//! user's own programs cannot rewrite. A service inside the session could do
//! neither, which is exactly why the online-accounts list it replaces was
//! decorative — anyone could edit the file and grant themselves anything.

mod agent;
mod audit;
mod auditnl;
mod excepcion;
mod identity;
mod local;
mod policy;
mod polkit;
mod procesos;
mod throttle;

use std::sync::Arc;

use tokio::sync::Mutex;
use zbus::fdo::{DBusProxy, Error as FdoError};
use zbus::message::Header;
use zbus::names::BusName;
use zbus::{interface, Connection};

use agent::{AgentRegistry, SharedAgents};
use identity::PinnedCaller;
use policy::PolicyStore;
use throttle::{NoticeThrottle, PromptThrottle};
use vasak_permissions_protocol::{
    Decision, PermissionRequest, Resource, SERVICE_INTERFACE, SERVICE_NAME, SERVICE_PATH,
};

struct PermissionService {
    store: PolicyStore,
    agents: SharedAgents,
    /// Serialises the read-modify-write of a policy file. Two programs asking
    /// at the same moment would otherwise each load the file, record their own
    /// answer and write it back, and whichever finished last would erase the
    /// other's decision.
    write_lock: Arc<Mutex<()>>,
    /// Ceiling on how many dialogs a person can be shown at once.
    throttle: Arc<Mutex<PromptThrottle>>,
    /// Cada cuánto se repite el aviso de un mismo bloqueo.
    ///
    /// Hace falta porque quien hace cumplir un permiso pregunta **por cada
    /// conexión**: un navegador que abre tres a PipeWire consultaría tres veces
    /// por lo mismo antes de que la primera quede anotada.
    notices: Arc<Mutex<NoticeThrottle>>,
    /// Lo que algún perfil ajeno bloqueó y todavía nadie decidió.
    ///
    /// Va acá y no en la política porque es otra cosa: la política guarda
    /// decisiones sobre recursos con nombre, y esto es una lista de hechos —tal
    /// perfil no dejó abrir tal ruta— que existe hasta que alguien la resuelve.
    pendientes: crate::local::Pendientes,
}

/// Rejects anything this service cannot honour.
///
/// An unrecognised id is a bug or an attempt to litter the policy with entries
/// the settings screen can never show. A recognised one that nothing enforces
/// is worse: the person would be asked a question, the answer would be stored,
/// and it would change nothing — while looking exactly like a decision that
/// held.
///
/// `key` es la identidad contra la que se iba a guardar, y hace falta porque la
/// respuesta no es la misma para las dos clases que hay. La captura de pantalla
/// no cambia nada anotada contra la ruta de un ejecutable —nadie la consulta
/// por ahí— y sí contra una identidad del portal, que es de donde llega.
fn check_resource(resource_id: &str, key: &str) -> Result<(), FdoError> {
    match Resource::from_id(resource_id) {
        Some(resource) if resource.decision_has_effect_for(key) => Ok(()),
        Some(_) => Err(FdoError::NotSupported(format!(
            "'{resource_id}' todavía no se puede hacer cumplir en VasakOS para \
             '{key}': lo entrega PipeWire o el portal de escritorio, que por ese \
             camino no consultan este servicio, y no hay perfil que lo niegue. \
             No se guarda ninguna decisión al respecto."
        ))),
        None => Err(FdoError::InvalidArgs(format!(
            "recurso desconocido: '{resource_id}'"
        ))),
    }
}

/// Fija el proceso por el que un delegado pregunta, si puede preguntar por él.
///
/// Las dos comprobaciones que separan a un delegado de cualquier otro llamante,
/// juntas y en este orden, para que `CheckPermissionFor` y `QueryPermissionFor`
/// no puedan separarse:
///
/// 1. Que quien pregunta sea uno de los [`DELEGATE_BINARIES`], por la ruta de
///    su ejecutable fijado. Antes de tocar al sujeto: a un programa cualquiera
///    no se le contesta nada sobre otro proceso, ni siquiera si existe.
/// 2. Que el sujeto sea de su usuario, salvo que el delegado corra como root.
///    El servicio de cuentas corre como root y habla por cualquiera; el
///    sincronizador y WirePlumber corren como la persona, y por un proceso de
///    otro usuario se les niega **sin diálogo** — la negativa llega antes de
///    `decide`, que es lo único que pregunta. Ver
///    [`identity::delegate_may_speak_for`].
///
/// Recibe la ruta y el uid del delegado ya resueltos, y no el mensaje, para
/// poder probar la regla sin un bus.
///
/// [`DELEGATE_BINARIES`]: vasak_permissions_protocol::DELEGATE_BINARIES
fn pin_delegated_subject(
    delegate_binary: &str,
    delegate_uid: u32,
    subject_pid: u32,
    subject_start_time: u64,
) -> Result<PinnedCaller, FdoError> {
    if !vasak_permissions_protocol::is_delegate(delegate_binary) {
        return Err(FdoError::AccessDenied(format!(
            "{delegate_binary} no puede consultar permisos en nombre de otro proceso"
        )));
    }

    let subject = PinnedCaller::capture_subject(subject_pid, subject_start_time)
        .map_err(FdoError::InvalidArgs)?;

    if !identity::delegate_may_speak_for(delegate_uid, subject.uid) {
        tracing::warn!(
            "{delegate_binary} (usuario {delegate_uid}) quiso preguntar por el \
             proceso {subject_pid}, que es del usuario {}. Se niega sin preguntar",
            subject.uid
        );
        return Err(FdoError::AccessDenied(
            "el proceso indicado pertenece a otro usuario".into(),
        ));
    }

    Ok(subject)
}

/// Pins the caller of the current message and resolves who it is.
async fn caller_of(connection: &Connection, header: &Header<'_>) -> Result<PinnedCaller, FdoError> {
    let sender = header
        .sender()
        .ok_or_else(|| FdoError::Failed("el mensaje no tiene remitente".into()))?;

    let proxy = DBusProxy::new(connection)
        .await
        .map_err(|e| FdoError::Failed(format!("no se pudo consultar al bus: {e}")))?;

    let name = BusName::from(sender.clone());
    let pid = proxy
        .get_connection_unix_process_id(name.clone())
        .await
        .map_err(|e| FdoError::Failed(format!("no se pudo obtener el PID de {sender}: {e}")))?;
    let uid = proxy
        .get_connection_unix_user(name)
        .await
        .map_err(|e| FdoError::Failed(format!("no se pudo obtener el usuario de {sender}: {e}")))?;

    // Pin immediately: between the bus telling us the PID and us reading its
    // executable, the process could exit and its number be handed to another.
    PinnedCaller::capture(pid, uid).map_err(FdoError::Failed)
}

impl PermissionService {
    /// Identifica al llamante y exige que sea el agente instalado.
    ///
    /// La comprobación es contra una ruta absoluta y nada más, igual que la del
    /// registro del agente: emparejar por nombre de archivo dejaría que un
    /// programa llamado `vasak-permissions-agent` en la carpeta de la persona
    /// se anotara permisos a nombre de cualquier aplicación.
    async fn solo_el_agente(
        &self,
        connection: &Connection,
        header: &Header<'_>,
    ) -> Result<PinnedCaller, FdoError> {
        let caller = caller_of(connection, header).await?;
        if !crate::agent::is_the_agent(&caller.binary_path()) {
            return Err(FdoError::AccessDenied(format!(
                "sólo el agente de permisos puede tocar las decisiones del \
                 portal; se rechazó {}",
                caller.binary_path()
            )));
        }
        Ok(caller)
    }

    /// Looks up the stored answer, asks the user when there is none, and
    /// remembers what they said.
    /// Deja constancia de un bloqueo que nadie preguntó, y avisa una vez.
    ///
    /// `QueryPermissionFor` contesta sin preguntar, que es lo correcto —el
    /// módulo de WirePlumber ve al cliente al conectarse, y «¿le permitís la
    /// cámara a pactl?» no es una pregunta que alguien pueda contestar—, pero
    /// así como estaba dejaba a la persona sin nada: la aplicación no figuraba
    /// en Privacidad y seguridad, así que no había interruptor que mover, y la
    /// negación no se veía. Bloquear sin poder desbloquear es justo lo que este
    /// servicio existe para no hacer.
    ///
    /// Así que un `unknown` que se va a hacer cumplir se anota y se avisa, igual
    /// que ya se hacía con lo que niega AppArmor. Anotarlo es lo que hace que
    /// después se pueda decidir; avisar es lo que hace que se pueda decidir
    /// ahora.
    ///
    /// Sólo con `unknown`. Un `denied` es una decisión de la persona, y repetir
    /// el aviso de algo que ya contestó es insistir.
    async fn anotar_y_avisar(
        &self,
        connection: &Connection,
        subject: &PinnedCaller,
        resource_id: &str,
    ) {
        let application = subject.describe();

        let primera_vez = self.notices.lock().await.should_notify(
            subject.uid,
            &application.binary_path,
            resource_id,
            std::time::Instant::now(),
        );
        if !primera_vez {
            return;
        }

        crate::audit::registrar_el_intento(
            &self.store,
            &self.write_lock,
            subject.uid,
            &application,
            resource_id,
        )
        .await;

        tracing::info!(
            "Sin decisión para '{resource_id}' de {}; se anota y se avisa al usuario {}",
            application.binary_path,
            subject.uid
        );

        // Aparte: quien pregunta esto está esperando para dejar pasar o no a un
        // cliente que se está conectando, y un agente lento no puede demorar
        // eso.
        //
        // Con el mismo cupo que los avisos de AppArmor, y no con uno propio: lo
        // que se protege es a la persona y al bus, que no distinguen de cuál de
        // los dos caminos vino el aviso. El silencio de arriba no alcanza acá —
        // una andanada de aplicaciones **distintas** son claves distintas, y sin
        // techo cada una abriría su tarea.
        let permiso = match crate::audit::cupo().clone().try_acquire_owned() {
            Ok(permiso) => permiso,
            Err(_) => {
                tracing::debug!("Demasiados avisos a la vez; se descarta el de {resource_id}");
                return;
            }
        };

        let connection = connection.clone();
        let agents = self.agents.clone();
        let uid = subject.uid;
        let resource_id = resource_id.to_string();
        tokio::spawn(async move {
            let _permiso = permiso;
            crate::agent::avisar_de_bloqueo_por_id(
                &connection,
                &agents,
                uid,
                &application,
                &resource_id,
            )
            .await;
        });
    }

    async fn decide(
        &self,
        connection: &Connection,
        subject: &PinnedCaller,
        resource_id: &str,
        detail: String,
    ) -> zbus::fdo::Result<bool> {
        let application = subject.describe();

        // Antes que nada, incluso antes de mirar lo que ya se decidió: si el
        // programa está pidiendo algo fuera de su alcance declarado, no hay
        // pregunta que hacer.
        //
        // Que el gestor de archivos pida el correo no es una decisión de la
        // persona — es un fallo o un ataque—, y mostrarle un diálogo la pondría
        // a autorizar exactamente lo que la lista existe para impedir. Se niega
        // sin preguntar y sin guardar nada.
        if !vasak_permissions_protocol::may_request(&application.binary_path, resource_id) {
            tracing::warn!(
                "FUERA DE ALCANCE — {} pidió '{resource_id}', que no está entre \
                 los recursos que puede usar. Se deniega sin preguntar",
                application.binary_path,
            );
            return Ok(false);
        }

        let stored = self
            .store
            .load(subject.uid)
            .map_err(FdoError::Failed)?
            .decision(&application.binary_path, resource_id);

        let decision = match stored {
            Decision::Allowed | Decision::Denied => stored,
            Decision::Unknown => {
                // Refuse without asking once the person has been shown enough
                // dialogs at once. Nothing is recorded: a burst of noise must
                // not permanently deny a program whose dialog was never seen.
                let within_ceiling = self
                    .throttle
                    .lock()
                    .await
                    .allow(subject.uid, std::time::Instant::now());

                if !within_ceiling {
                    tracing::warn!(
                        "Demasiadas consultas de permiso seguidas; se deniega \
                         '{resource_id}' a {} sin preguntar",
                        application.binary_path
                    );
                    return Ok(false);
                }

                let request = PermissionRequest {
                    // Este camino es el de los recursos con nombre, que no
                    // vienen de un perfil: la decisión se guarda por programa.
                    profile: String::new(),
                    application: application.clone(),
                    resource_id: resource_id.to_string(),
                    detail,
                };

                let Some(answer) =
                    agent::ask(connection, &self.agents, subject.uid, &request).await
                else {
                    // The question could not be put to anyone — no agent yet,
                    // or it never answered. Refuse, but remember nothing:
                    // recording this would deny anything that asked during
                    // login for good, and the user would never see a dialog.
                    // Give the slot back too, since no dialog was displayed.
                    self.throttle.lock().await.refund(subject.uid);
                    return Ok(false);
                };

                // A real answer is remembered, refusals included. Storing
                // nothing would re-open the same dialog on the program's very
                // next attempt, and the person could never settle it.
                let _guard = self.write_lock.lock().await;
                let mut policy = self.store.load(subject.uid).map_err(FdoError::Failed)?;
                // `true`: llegó acá porque el programa preguntó, así que va a
                // respetar lo que se conteste aunque ningún perfil lo limite.
                policy.record(
                    &application,
                    resource_id,
                    Decision::from_answer(answer),
                    true,
                );
                self.store
                    .save(subject.uid, &policy)
                    .map_err(FdoError::Failed)?;

                Decision::from_answer(answer)
            }
        };

        if !decision.is_allowed() {
            tracing::info!(
                "Denegado '{resource_id}' a {} (PID {})",
                application.binary_path,
                subject.pid
            );
        }

        Ok(decision.is_allowed())
    }
}

#[interface(name = "ar.net.vasak.os.Permissions")]
impl PermissionService {
    /// Whether the calling program may use `resource_id`, asking the user the
    /// first time and remembering the answer.
    ///
    /// `detail` carries context for the dialog — for an online account, which
    /// account is being asked for. It never affects the stored decision, so a
    /// program cannot get a second, differently-worded question by changing it.
    async fn check_permission(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        resource_id: String,
        detail: String,
    ) -> zbus::fdo::Result<bool> {
        // Detrás de identificar al llamante, y no antes: si el recurso se puede
        // hacer cumplir depende de contra qué identidad se guardaría.
        let caller = caller_of(connection, &header).await?;
        check_resource(&resource_id, &caller.binary_path())?;

        self.decide(connection, &caller, &resource_id, detail).await
    }

    /// The same question, asked by a service on behalf of the program that
    /// called *it*.
    ///
    /// Needed because an application does not reach this service directly for an
    /// online account: it asks the account service, which then has to ask here.
    /// Without naming the original program, every application would share one
    /// decision recorded against the account service — which is no decision.
    ///
    /// Only the delegates listed in the protocol may call this, identified the
    /// same way as anyone else: by the executable behind their pinned PID.
    async fn check_permission_for(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        subject_pid: u32,
        subject_start_time: u64,
        resource_id: String,
        detail: String,
    ) -> zbus::fdo::Result<bool> {
        let delegate = caller_of(connection, &header).await?;
        // Un delegado sin privilegios queda confinado a su propio usuario. El
        // de sistema —root, que es como corre el de cuentas porque los tokens
        // viven en archivos de root— habla por cualquiera: es el único que
        // puede, y para eso existe. Ver `pin_delegated_subject`.
        let subject = pin_delegated_subject(
            &delegate.binary_path(),
            delegate.uid,
            subject_pid,
            subject_start_time,
        )?;

        // Contra el sujeto, que es contra quien se guarda: el delegado sólo
        // transporta la pregunta.
        check_resource(&resource_id, &subject.binary_path())?;

        self.decide(connection, &subject, &resource_id, detail)
            .await
    }

    /// Lo que ya se decidió para otro proceso, **sin preguntar nada**.
    ///
    /// `CheckPermissionFor` no sirve para hacer cumplir un permiso desde un
    /// punto que no es una acción de la persona. Ese método pregunta cuando no
    /// sabe, y quien hace cumplir suele enterarse en el peor momento para
    /// preguntar: el módulo de WirePlumber ve a cada cliente **al conectarse**,
    /// y «¿le permitís la cámara a pactl?» no es una pregunta que alguien
    /// pueda contestar. Preguntarla en cada conexión enseñaría a conceder sin
    /// leer, que es exactamente lo que este servicio existe para no hacer.
    ///
    /// Así que acá se lee y no se pregunta: devuelve `allowed`, `denied` o
    /// `unknown`, no abre diálogo y **no guarda nada**. Quien pregunta con
    /// contexto es el portal, que sabe qué aplicación lo pidió y para qué.
    ///
    /// `unknown` no es «permitido»: quien llame tiene que tratarlo como
    /// negado. Se devuelve aparte de `denied` porque son cosas distintas —una
    /// es una decisión de la persona y la otra es que todavía no la tomó— y la
    /// pantalla de Privacidad y seguridad las muestra distinto.
    async fn query_permission_for(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        subject_pid: u32,
        subject_start_time: u64,
        resource_id: String,
    ) -> zbus::fdo::Result<String> {
        let delegate = caller_of(connection, &header).await?;
        let subject = pin_delegated_subject(
            &delegate.binary_path(),
            delegate.uid,
            subject_pid,
            subject_start_time,
        )?;

        check_resource(&resource_id, &subject.binary_path())?;

        // Fuera del alcance declarado no hay nada que leer: es «no», igual que
        // en `decide`, y por el mismo motivo — que el gestor de archivos pida
        // el correo es un fallo o un ataque, no una decisión pendiente.
        if !vasak_permissions_protocol::may_request(&subject.binary_path(), &resource_id) {
            return Ok(Decision::Denied.as_id().to_string());
        }

        let stored = self
            .store
            .load(subject.uid)
            .map_err(FdoError::Failed)?
            .decision(&subject.binary_path(), &resource_id);

        if stored == Decision::Unknown {
            self.anotar_y_avisar(connection, &subject, &resource_id)
                .await;
        }

        Ok(stored.as_id().to_string())
    }

    /// Everything decided for the calling user, as JSON, for the settings
    /// screen. A caller only ever sees its own user's policy.
    async fn list_permissions(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let caller = caller_of(connection, &header).await?;
        let policy = self.store.load(caller.uid).map_err(FdoError::Failed)?;

        serde_json::to_string(&policy.entries())
            .map_err(|e| FdoError::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Grants or revokes a permission from the settings screen.
    ///
    /// Behind polkit, and that is not a formality: without it any program could
    /// call this and grant itself what it had just been refused, which would
    /// make the entire service decorative.
    async fn set_permission(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        binary_path: String,
        resource_id: String,
        allowed: bool,
    ) -> zbus::fdo::Result<()> {
        check_resource(&resource_id, &binary_path)?;

        // Conceder algo fuera del alcance de un programa se rechaza acá también,
        // y no sólo en `decide`.
        //
        // Si no, la pantalla podría escribir «permitido» sobre un recurso que el
        // programa no puede pedir: `decide` lo negaría igual, así que quedaría un
        // interruptor encendido que no hace nada — la clase de mentira que este
        // servicio existe para no contar. Negarlo sí se acepta: no cambia el
        // resultado, pero tampoco engaña a nadie.
        if allowed && !vasak_permissions_protocol::may_request(&binary_path, &resource_id) {
            return Err(FdoError::AccessDenied(format!(
                "{binary_path} no puede usar '{resource_id}': está fuera de los \
                 recursos que esa aplicación tiene declarados, así que permitirlo \
                 no tendría ningún efecto"
            )));
        }

        let caller = caller_of(connection, &header).await?;
        polkit::authorize(connection, &caller).await?;

        let _guard = self.write_lock.lock().await;
        let mut policy = self.store.load(caller.uid).map_err(FdoError::Failed)?;

        // Describe the target program from the path being managed, not from
        // the caller: the settings screen is editing somebody else's entry.
        let application = identity::describe_path(&binary_path);

        // Una identidad del portal no es un archivo, así que no hay perfil que
        // tocar: se guarda y se termina.
        //
        // No es un atajo. `permitidos_de` diría que la cámara está permitida y
        // `aplicar` intentaría escribir un perfil enganchado a
        // `portal:com.google.Chrome`, que no es una ruta absoluta —lo rechaza
        // `excepcion`, y con razón—, y el error volvería como si no se hubiera
        // podido guardar la decisión. O sea que sin esta rama el interruptor de
        // la pantalla fallaría siempre, que es justo lo que este cambio existe
        // para arreglar.
        if vasak_permissions_protocol::is_portal_key(&binary_path) {
            policy.record(
                &application,
                &resource_id,
                Decision::from_answer(allowed),
                true,
            );
            return self
                .store
                .save(caller.uid, &policy)
                .map_err(FdoError::Failed);
        }

        // Lo que estaba concedido antes, para poder volver atrás si el guardado
        // falla después de haber tocado el perfil.
        let antes = excepcion::permitidos_de(&policy, &binary_path);
        // `false`: esto es la pantalla fijando una decisión, no el programa
        // preguntando. Si ya era de los que preguntan, `record` lo conserva.
        policy.record(
            &application,
            &resource_id,
            Decision::from_answer(allowed),
            false,
        );
        let ahora = excepcion::permitidos_de(&policy, &binary_path);

        // Primero el perfil, después el archivo de decisiones.
        //
        // El orden no es indiferente y las dos formas de fallar son distintas.
        // Guardando primero, un fallo al aplicar dejaría una decisión escrita
        // que el sistema no cumple: quien la tomó creería que la cámara quedó
        // permitida —o negada— y no sería cierto.
        //
        // Aplicando primero, un fallo deja todo como estaba y el error llega a
        // quien pidió el cambio, que es lo que corresponde. Y si lo que falla
        // es el guardado, se deshace el perfil para que el kernel y el disco no
        // queden diciendo cosas distintas.
        if let Err(error) = excepcion::aplicar(&binary_path, &ahora) {
            tracing::warn!("No se pudo aplicar el perfil de {binary_path}: {error}");
            return Err(FdoError::Failed(format!(
                "la decisión no se guardó porque no se pudo aplicar: {error}"
            )));
        }

        if let Err(error) = self.store.save(caller.uid, &policy) {
            if let Err(otro) = excepcion::aplicar(&binary_path, &antes) {
                // Deshacer también falló. Se registra fuerte: el perfil quedó
                // en un estado que el archivo de decisiones no describe.
                tracing::error!(
                    "No se pudo guardar la decisión de {binary_path} ni deshacer \
                     el perfil ({otro}); el sistema quedó inconsistente"
                );
            }
            return Err(FdoError::Failed(error));
        }
        Ok(())
    }

    /// Forgets a program entirely, so the next time it asks the user is asked
    /// again. Also behind polkit.
    async fn forget_permission(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        binary_path: String,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_of(connection, &header).await?;
        polkit::authorize(connection, &caller).await?;

        let _guard = self.write_lock.lock().await;
        let mut policy = self.store.load(caller.uid).map_err(FdoError::Failed)?;
        policy.forget(&binary_path);

        self.store
            .save(caller.uid, &policy)
            .map_err(FdoError::Failed)
    }

    /// Lo que se decidió para una aplicación que llegó por el portal.
    ///
    /// La contesta el backend del portal **antes** de abrir ningún diálogo. Sin
    /// esto la respuesta se preguntaba y se descartaba: Chrome llegó a pedir
    /// compartir la pantalla cuatro veces en veinte segundos, y no había nada
    /// que retirar después.
    ///
    /// Devuelve `allowed`, `denied` o `unknown`, que es lo que hay que
    /// distinguir: sólo el tercero abre el diálogo. Un booleano obligaría a
    /// convertir «todavía no se decidió» en un «no», y entonces lo que una vez
    /// se rechazó nunca se volvería a preguntar y lo que nunca se preguntó
    /// quedaría rechazado para siempre.
    ///
    /// **Sólo el agente.** Este método lee la política de quien llama, así que
    /// contestarle a cualquiera diría qué tiene permitido una persona a
    /// cualquier programa que sepa hablar D-Bus.
    async fn portal_decision(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        app_id: String,
        resource_id: String,
    ) -> zbus::fdo::Result<String> {
        let caller = self.solo_el_agente(connection, &header).await?;

        let Some(key) = vasak_permissions_protocol::portal_key(&app_id) else {
            // Sin identidad utilizable no hay nada guardado que buscar. Se
            // contesta «sin decidir», que deja al agente preguntando cada vez
            // —lo de siempre— en vez de inventar una respuesta.
            return Ok(Decision::Unknown.as_id().to_string());
        };
        check_resource(&resource_id, &key)?;

        let decision = self
            .store
            .load(caller.uid)
            .map_err(FdoError::Failed)?
            .decision(&key, &resource_id);

        Ok(decision.as_id().to_string())
    }

    /// Anota lo que la persona contestó en el diálogo del portal.
    ///
    /// ── Por qué esto no pasa por polkit ─────────────────────────────────────
    ///
    /// `SetPermission` sí pasa, y la diferencia no es un descuido. Ahí la
    /// pantalla de configuración cambia una decisión **ya tomada**, y sin
    /// autenticar cualquier programa podría concederse lo que se le acababa de
    /// negar. Acá lo que se anota es la respuesta que la persona acaba de dar
    /// en un diálogo que apareció por algo que ella misma hizo. Pedirle la
    /// contraseña encima del «permitir» que ya apretó es enseñarle a tipearla
    /// sin leer, y eso cuesta más de lo que cuida.
    ///
    /// Lo que sostiene el método es lo otro: sólo lo puede llamar el agente
    /// instalado, que es el único que muestra ese diálogo. Sin esa comprobación
    /// cualquier programa local se anotaría la cámara a nombre de Chrome sin
    /// que apareciera nada en pantalla, que es peor que no guardar nada.
    async fn record_portal_decision(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        app_id: String,
        resource_id: String,
        allowed: bool,
    ) -> zbus::fdo::Result<()> {
        let caller = self.solo_el_agente(connection, &header).await?;

        let key = vasak_permissions_protocol::portal_key(&app_id).ok_or_else(|| {
            FdoError::InvalidArgs(format!(
                "'{app_id}' no sirve como identidad de aplicación, así que no se \
                 guarda ninguna decisión a su nombre"
            ))
        })?;
        check_resource(&resource_id, &key)?;

        let application = identity::describe_path(&key);

        let _guard = self.write_lock.lock().await;
        let mut policy = self.store.load(caller.uid).map_err(FdoError::Failed)?;
        // `true`: el portal pregunta antes de entregar el recurso y respeta la
        // respuesta, que es lo que este campo quiere decir. Sin él la pantalla
        // mostraría el interruptor apagado por no tener perfil que lo sostenga.
        policy.record(
            &application,
            &resource_id,
            Decision::from_answer(allowed),
            true,
        );
        self.store
            .save(caller.uid, &policy)
            .map_err(FdoError::Failed)?;

        tracing::info!(
            "Portal: '{resource_id}' {} para {app_id}",
            if allowed { "permitido" } else { "denegado" }
        );
        Ok(())
    }

    /// Lo que algún perfil bloqueó y todavía nadie decidió.
    ///
    /// Sale como JSON por la misma razón que las consultas de permiso: la forma
    /// vive en un solo lugar y no se repite como firma de D-Bus en cada lado.
    ///
    /// No pide autorización: leer qué se bloqueó no concede nada, y pedir la
    /// contraseña para *mirar* haría que la pantalla de seguridad la pida al
    /// abrirse, que es la forma más rápida de que la gente aprenda a tipearla
    /// sin leer.
    ///
    /// Pero sí se mira **quién** pregunta, y se devuelve sólo lo suyo. Este
    /// servicio atiende a todos los del equipo y la lista lleva rutas de
    /// archivos: devolverla entera contaría qué tiene otra persona en su
    /// carpeta a cualquiera que sepa llamar a un método de D-Bus.
    async fn list_blocked(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let caller = caller_of(connection, &header).await?;
        let lista = crate::local::listar(&self.pendientes, caller.uid);
        serde_json::to_string(&lista)
            .map_err(|e| FdoError::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Permite exactamente lo que se bloqueó: ese perfil, esa ruta, esos
    /// permisos.
    ///
    /// Detrás de polkit, como todo lo que cambia la política. Escribe la
    /// excepción en `/etc/apparmor.d/local/<perfil>` y recarga el perfil, así
    /// que tiene efecto sin reiniciar nada.
    ///
    /// La ruta y los permisos **no** se toman del llamador: se buscan en la
    /// lista de bloqueos por perfil y ruta. Aceptar una máscara arbitraria
    /// dejaría que un programa pidiera `rwlkm` sobre algo que sólo se le negó
    /// leer, y la persona estaría autorizando más de lo que la pantalla dice.
    async fn allow_blocked(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        profile: String,
        path: String,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_of(connection, &header).await?;
        polkit::authorize(connection, &caller).await?;

        // Sólo de la propia lista: si no, alguien podría permitirle a un
        // programa de otra persona el acceso a un archivo de ella.
        let bloqueo = crate::local::listar(&self.pendientes, caller.uid)
            .into_iter()
            .find(|b| b.perfil == profile && b.ruta == path)
            .ok_or_else(|| FdoError::InvalidArgs("ese bloqueo ya no está en la lista".into()))?;

        let regla = crate::local::regla_para(&bloqueo.ruta, &bloqueo.mascara)
            .map_err(|m| FdoError::InvalidArgs(m.to_string()))?;

        let _guard = self.write_lock.lock().await;
        // El archivo y el kernel se mueven juntos o no se mueve ninguno.
        crate::local::conceder_y_recargar(&bloqueo.perfil, &regla, &crate::local::raiz())
            .map_err(FdoError::Failed)?;

        // Recién ahora sale de la lista: sacarlo antes de que la política esté
        // en efecto dejaría a la persona sin el aviso y sin el permiso.
        crate::local::quitar(&self.pendientes, caller.uid, &profile, &path);
        Ok(())
    }

    /// Saca un bloqueo de la lista sin permitirlo: la respuesta es que no.
    ///
    /// No hace falta autorizar: no conceder nada es el estado en el que ya
    /// estaba, así que esto no cambia lo que el sistema permite.
    async fn dismiss_blocked(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        profile: String,
        path: String,
    ) -> zbus::fdo::Result<()> {
        // Sin autorizar, pero sólo sobre lo propio: descartar el bloqueo de otra
        // persona le sacaría de la vista algo que ella todavía tiene que
        // decidir, y no volvería a aparecer hasta el próximo intento.
        let caller = caller_of(connection, &header).await?;
        crate::local::quitar(&self.pendientes, caller.uid, &profile, &path);
        Ok(())
    }

    /// Vuelve a bloquear algo que se había permitido.
    async fn revoke_blocked(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        profile: String,
        rule: String,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_of(connection, &header).await?;
        polkit::authorize(connection, &caller).await?;

        let _guard = self.write_lock.lock().await;
        crate::local::revocar_y_recargar(&profile, &rule, &crate::local::raiz())
            .map_err(FdoError::Failed)
    }

    /// Lo que ya se le permitió a un perfil, para poder retirarlo.
    async fn list_allowed(&self, profile: String) -> zbus::fdo::Result<String> {
        if !crate::local::perfil_valido(&profile) {
            return Err(FdoError::InvalidArgs("nombre de perfil inválido".into()));
        }
        let reglas = crate::local::concedidas_en(&profile, &crate::local::raiz());
        serde_json::to_string(&reglas)
            .map_err(|e| FdoError::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Offers this connection as the dialog agent for the calling user.
    ///
    /// Accepted only from the installed agent binary — see `AgentRegistry`.
    async fn register_agent(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        object_path: String,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_of(connection, &header).await?;
        let sender = header
            .sender()
            .ok_or_else(|| FdoError::Failed("el mensaje no tiene remitente".into()))?
            .to_string();

        self.agents
            .lock()
            .await
            .register(caller.uid, &caller.binary_path(), sender, object_path)
            .map_err(FdoError::AccessDenied)?;

        tracing::info!(
            "Agente de permisos registrado para el usuario {}",
            caller.uid
        );
        Ok(())
    }
}

/// Drops agents whose connection has gone, so a later request fails fast
/// instead of waiting out the answer timeout against a name nobody owns.
async fn watch_for_departed_agents(connection: Connection, agents: SharedAgents) {
    use futures_util::StreamExt;

    let proxy = match DBusProxy::new(&connection).await {
        Ok(proxy) => proxy,
        Err(error) => {
            tracing::error!("No se pudo vigilar el bus: {error}");
            return;
        }
    };

    let mut changes = match proxy.receive_name_owner_changed().await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::error!("No se pudo escuchar NameOwnerChanged: {error}");
            return;
        }
    };

    while let Some(signal) = changes.next().await {
        let Ok(args) = signal.args() else { continue };
        // An empty new owner means the name went away.
        if args.new_owner().is_none() {
            agents.lock().await.forget_connection(args.name());
        }
    }
}

/// The system bus, always, in a released build.
///
/// Debug builds can be pointed at a session bus to exercise the service
/// without root. The escape hatch is compiled out of release entirely rather
/// than guarded at runtime: a permission service that could be moved onto a
/// bus the user controls would be no service at all.
#[cfg(debug_assertions)]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    if std::env::var_os("VASAK_PERMISSIONS_TEST_ROOT").is_some() {
        tracing::warn!("MODO DE DESARROLLO: usando el bus de sesión");
        return zbus::connection::Builder::session();
    }
    zbus::connection::Builder::system()
}

#[cfg(not(debug_assertions))]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    zbus::connection::Builder::system()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let agents: SharedAgents = Arc::new(Mutex::new(AgentRegistry::default()));

    // El vigilante del registro del kernel también anota decisiones, así que
    // comparte el almacén y —sobre todo— el mismo candado de escritura: son dos
    // escritores sobre el mismo archivo.
    let store = PolicyStore::from_environment();
    let write_lock = Arc::new(Mutex::new(()));
    let store_para_el_vigilante = store.clone();
    let write_lock_para_el_vigilante = Arc::clone(&write_lock);

    let pendientes = local::pendientes_nuevos();

    let service = PermissionService {
        store,
        agents: Arc::clone(&agents),
        write_lock,
        throttle: Arc::new(Mutex::new(PromptThrottle::default())),
        notices: Arc::new(Mutex::new(NoticeThrottle::default())),
        pendientes: Arc::clone(&pendientes),
    };

    let connection = service_bus()?
        .name(SERVICE_NAME)?
        .serve_at(SERVICE_PATH, service)?
        .build()
        .await?;

    tokio::spawn(watch_for_departed_agents(
        connection.clone(),
        agents.clone(),
    ));
    // Avisa de lo que los perfiles de AppArmor bloquean. Sin esto, el bloqueo
    // es correcto pero invisible: se ve una cámara que no anda y nadie sabe por
    // qué.
    // La caché de pid → ruta, que llena un hilo escuchando los arranques de
    // proceso del kernel. Es lo que permite nombrar a un programa que se cerró
    // apenas se le negó el acceso, que es el caso más común.
    let procesos = procesos::cache_nueva();
    let procesos_para_el_hilo = Arc::clone(&procesos);
    std::thread::spawn(move || procesos::escuchar(procesos_para_el_hilo));

    tokio::spawn(audit::vigilar(
        connection.clone(),
        agents,
        store_para_el_vigilante,
        write_lock_para_el_vigilante,
        procesos,
        pendientes.clone(),
    ));

    tracing::info!("{SERVICE_NAME} escuchando en {SERVICE_PATH} ({SERVICE_INTERFACE})");
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod delegation_tests {
    use super::*;

    /// El uid con el que corre la prueba, leído de donde lo lee el demonio para
    /// el sujeto: el dueño de `/proc/<pid>`.
    fn own_uid() -> u32 {
        std::os::unix::fs::MetadataExt::uid(&std::fs::metadata("/proc/self").expect("/proc/self"))
    }

    /// El proceso de la prueba como sujeto: existe, está vivo y su momento de
    /// arranque es el de verdad.
    fn own_process() -> (u32, u64) {
        let pid = std::process::id();
        let start_time = crate::polkit::start_time_of(pid).expect("momento de arranque");
        (pid, start_time)
    }

    /// Un uid que no es el de la prueba ni root, sea quien sea quien la corre.
    fn someone_else(uid: u32) -> u32 {
        if uid == 1 {
            2
        } else {
            uid.wrapping_add(1).max(1)
        }
    }

    fn is_access_denied(result: &Result<PinnedCaller, FdoError>) -> bool {
        matches!(result, Err(FdoError::AccessDenied(_)))
    }

    /// El caso para el que el sincronizador entró en la lista: una aplicación
    /// de la misma persona le pide lo guardado y él pregunta en su nombre.
    #[test]
    fn el_sincronizador_pregunta_por_un_proceso_de_su_propio_usuario() {
        let (pid, start_time) = own_process();
        let subject =
            pin_delegated_subject("/usr/bin/vasak-accounts-sync", own_uid(), pid, start_time)
                .expect("un proceso de su propio usuario tiene que poder nombrarlo");
        assert_eq!(subject.pid, pid);
        assert_eq!(subject.uid, own_uid());
    }

    /// Y por uno de otro usuario, no: se niega antes de `decide`, que es lo
    /// único que abre un diálogo. Si esto pasara, una copia del sincronizador
    /// corrida por cualquiera leería las decisiones de otra persona en el valor
    /// de retorno y le abriría diálogos en su sesión.
    #[test]
    fn el_sincronizador_no_pregunta_por_un_proceso_de_otro_usuario() {
        let (pid, start_time) = own_process();
        let delegate_uid = someone_else(own_uid());

        let result = pin_delegated_subject(
            "/usr/bin/vasak-accounts-sync",
            delegate_uid,
            pid,
            start_time,
        );
        // El mensaje no lleva los uid: CodeQL marca cualquier camino de un uid a
        // una salida, aunque sea el texto de una prueba.
        assert!(
            is_access_denied(&result),
            "un delegado pudo preguntar por un proceso de otro usuario"
        );
    }

    /// La misma regla alcanza a WirePlumber, que también corre como la persona.
    /// No es una regla nueva para el sincronizador: es la de todo delegado sin
    /// privilegios.
    #[test]
    fn wireplumber_tampoco_pregunta_por_otro_usuario() {
        let (pid, start_time) = own_process();

        assert!(pin_delegated_subject("/usr/bin/wireplumber", own_uid(), pid, start_time).is_ok());
        assert!(is_access_denied(&pin_delegated_subject(
            "/usr/bin/wireplumber",
            someone_else(own_uid()),
            pid,
            start_time,
        )));
    }

    /// El servicio de cuentas corre como root y sigue hablando por cualquiera:
    /// sumar al sincronizador no le cambia nada.
    #[test]
    fn el_servicio_de_cuentas_como_root_sigue_hablando_por_cualquiera() {
        let (pid, start_time) = own_process();
        assert!(pin_delegated_subject("/usr/bin/vasak-accounts", 0, pid, start_time).is_ok());
    }

    /// Quien no es delegado no llega ni a fijar al sujeto: la respuesta es
    /// `AccessDenied` aunque el pid no exista, y no un error que diga si
    /// existe o no.
    #[test]
    fn un_programa_que_no_es_delegado_no_llega_al_sujeto() {
        for binary in [
            "/usr/bin/vasak-mail",
            "/home/alguien/.local/bin/vasak-accounts-sync",
            "/tmp/vasak-accounts-sync",
        ] {
            let result = pin_delegated_subject(binary, 0, 999_999_999, 0);
            assert!(is_access_denied(&result), "{binary}");
        }
    }

    /// Los tres del almacén se aceptan contra la ruta de un ejecutable, que es
    /// contra lo que el sincronizador va a preguntar.
    #[test]
    fn el_servicio_acepta_los_recursos_del_almacen() {
        for id in ["store.email", "store.calendar", "store.contacts"] {
            assert!(
                check_resource(id, "/usr/bin/vasak-contacts").is_ok(),
                "{id} no se acepta"
            );
        }
    }

    /// Un área inventada es un recurso desconocido, y contra una identidad del
    /// portal no hay nada que guardar: por ahí no llega ninguna lectura.
    #[test]
    fn el_servicio_rechaza_lo_que_no_es_del_almacen() {
        assert!(matches!(
            check_resource("store.algo", "/usr/bin/vasak-contacts"),
            Err(FdoError::InvalidArgs(_))
        ));
        let key =
            vasak_permissions_protocol::portal_key("com.google.Chrome").expect("identidad válida");
        assert!(matches!(
            check_resource("store.contacts", &key),
            Err(FdoError::NotSupported(_))
        ));
    }
}

#[cfg(test)]
mod tests_interfaz {
    use super::*;

    use zbus::object_server::Interface;

    fn un_servicio() -> PermissionService {
        PermissionService {
            store: PolicyStore::new(),
            agents: Arc::new(Mutex::new(AgentRegistry::default())),
            write_lock: Arc::new(Mutex::new(())),
            throttle: Arc::new(Mutex::new(PromptThrottle::default())),
            notices: Arc::new(Mutex::new(NoticeThrottle::default())),
            pendientes: Default::default(),
        }
    }

    fn introspeccion() -> String {
        let servicio = un_servicio();
        let mut xml = String::new();
        servicio.introspect_to_writer(&mut xml, 0);
        xml
    }

    /// La interfaz exporta los nombres que el agente llama.
    ///
    /// El agente los manda como cadenas; acá los genera zbus a partir del
    /// nombre de la función. Renombrar `portal_decision` compila de las dos
    /// puntas y deja al agente llamando a un método que no existe — y el fallo
    /// no se ve: la consulta falla, se devuelve «sin decidir», aparece el
    /// diálogo. O sea que se vería igual que antes de este cambio, que es la
    /// peor forma posible de romperse.
    #[test]
    fn los_metodos_del_portal_se_llaman_como_el_agente_cree() {
        let xml = introspeccion();

        for metodo in [
            vasak_permissions_protocol::PORTAL_DECISION_METHOD,
            vasak_permissions_protocol::RECORD_PORTAL_DECISION_METHOD,
        ] {
            assert!(
                xml.contains(&format!(r#"<method name="{metodo}">"#)),
                "la interfaz no exporta {metodo}:\n{xml}"
            );
        }
    }

    /// Y con la firma que el agente arma.
    ///
    /// `PortalDecision` recibe dos cadenas y **contesta** una: si contestara un
    /// booleano habría que convertir «todavía no se decidió» en un «no», y
    /// entonces lo que nunca se preguntó quedaría rechazado para siempre.
    /// `RecordPortalDecision` recibe dos cadenas y un booleano, y no contesta
    /// nada.
    #[test]
    fn los_metodos_del_portal_tienen_la_firma_que_el_agente_arma() {
        let xml = introspeccion();

        let consulta = bloque_del_metodo(&xml, vasak_permissions_protocol::PORTAL_DECISION_METHOD);
        assert_eq!(entradas(&consulta), vec!["s", "s"], "{consulta}");
        assert_eq!(salidas(&consulta), vec!["s"], "{consulta}");

        let anotar = bloque_del_metodo(
            &xml,
            vasak_permissions_protocol::RECORD_PORTAL_DECISION_METHOD,
        );
        assert_eq!(entradas(&anotar), vec!["s", "s", "b"], "{anotar}");
        assert!(salidas(&anotar).is_empty(), "{anotar}");
    }

    /// El método que lee la política sin preguntar existe y se llama como el
    /// módulo de WirePlumber cree.
    ///
    /// Ese módulo está escrito en C, no comparte nada de este código y lo
    /// nombra por una cadena. Un renombre de este lado compila perfecto y lo
    /// deja llamando a un método que no existe. Y como el módulo **falla
    /// cerrando**, eso no se vería como un error: se vería como la cámara
    /// apagada para todo el mundo, sin que nada diga por qué.
    #[test]
    fn la_consulta_sin_preguntar_se_llama_como_el_modulo_cree() {
        let xml = introspeccion();
        let metodo = vasak_permissions_protocol::QUERY_PERMISSION_FOR_METHOD;

        assert!(
            xml.contains(&format!(r#"<method name="{metodo}">"#)),
            "la interfaz no exporta {metodo}:\n{xml}"
        );
    }

    /// Y con la firma que el módulo arma: pid, instante de arranque y recurso;
    /// contesta una cadena.
    ///
    /// La cadena es a propósito y es la misma razón que en `PortalDecision`:
    /// si contestara un booleano habría que convertir «todavía no se decidió»
    /// en un «no», y se perdería la diferencia entre lo que la persona decidió
    /// y lo que nunca se le preguntó. El módulo trata las dos igual —niega—,
    /// pero la pantalla de Privacidad y seguridad no.
    ///
    /// El instante de arranque no es decorativo: es lo que impide que un pid
    /// reciclado apunte a otro programa entre que el cliente se conecta y que
    /// llega la consulta.
    #[test]
    fn la_consulta_sin_preguntar_tiene_la_firma_que_el_modulo_arma() {
        let xml = introspeccion();
        let bloque = bloque_del_metodo(
            &xml,
            vasak_permissions_protocol::QUERY_PERMISSION_FOR_METHOD,
        );

        assert_eq!(entradas(&bloque), vec!["u", "t", "s"], "{bloque}");
        assert_eq!(salidas(&bloque), vec!["s"], "{bloque}");
    }

    /// Y **no** se parece a `CheckPermissionFor`, que sí pregunta.
    ///
    /// Los dos toman pid y arranque, y confundirlos desde el módulo abriría un
    /// diálogo por cada cliente de PipeWire que se conecta — «¿le permitís la
    /// cámara a pactl?»—, que es justo lo que enseña a conceder sin leer. Se
    /// distinguen por la firma: el que pregunta toma además un `detail` para
    /// el diálogo y contesta un booleano.
    #[test]
    fn el_que_pregunta_y_el_que_no_no_se_pueden_confundir() {
        let xml = introspeccion();

        let pregunta = bloque_del_metodo(&xml, "CheckPermissionFor");
        let lee = bloque_del_metodo(
            &xml,
            vasak_permissions_protocol::QUERY_PERMISSION_FOR_METHOD,
        );

        assert_eq!(entradas(&pregunta), vec!["u", "t", "s", "s"], "{pregunta}");
        assert_eq!(salidas(&pregunta), vec!["b"], "{pregunta}");
        assert_ne!(entradas(&pregunta), entradas(&lee));
    }

    fn bloque_del_metodo(xml: &str, metodo: &str) -> String {
        let inicio = xml
            .find(&format!(r#"<method name="{metodo}">"#))
            .unwrap_or_else(|| panic!("no está {metodo} en:\n{xml}"));
        let resto = &xml[inicio..];
        let fin = resto.find("</method>").expect("el método tiene cierre");
        resto[..fin].to_string()
    }

    fn argumentos(bloque: &str, direccion: &str) -> Vec<String> {
        bloque
            .lines()
            .filter(|l| l.contains(&format!(r#"direction="{direccion}""#)))
            .filter_map(|l| {
                let tras = l.split(r#"type=""#).nth(1)?;
                Some(tras.split('"').next()?.to_string())
            })
            .collect()
    }

    fn entradas(bloque: &str) -> Vec<String> {
        argumentos(bloque, "in")
    }

    fn salidas(bloque: &str) -> Vec<String> {
        argumentos(bloque, "out")
    }
}
