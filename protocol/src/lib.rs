//! The contract between the permission service, the dialog agent and the
//! settings interface.
//!
//! Everything that travels over D-Bus is defined here once so the three sides
//! cannot drift apart: a field renamed on one end stops compiling on the other
//! instead of silently becoming a permission that never matches.

use serde::{Deserialize, Serialize};

// ── Bus addresses ───────────────────────────────────────────────────────────

/// The service runs on the **system** bus, as root.
///
/// It has to read `/proc/<pid>/exe` of arbitrary processes to know who is
/// asking, which an unprivileged process cannot do for someone else's
/// processes, and it has to own a policy file the user's own programs cannot
/// rewrite. A service in the user's session could do neither.
pub const SERVICE_NAME: &str = "ar.net.vasak.os.Permissions";
pub const SERVICE_PATH: &str = "/ar/net/vasak/os/Permissions";
pub const SERVICE_INTERFACE: &str = "ar.net.vasak.os.Permissions";

/// The dialog agent, on the session bus of whoever is logged in.
pub const AGENT_INTERFACE: &str = "ar.net.vasak.os.PermissionAgent";

/// The only executable accepted as the dialog agent.
///
/// This is the whole reason a malicious program cannot register itself as the
/// agent and approve everything on its own behalf: writing to `/usr/bin`
/// requires root, so no program running as you can occupy this path.
pub const AGENT_BINARY: &str = "/usr/bin/vasak-permissions-agent";

/// Los dos métodos que el agente llama por las decisiones del portal.
///
/// Acá y no sueltos en cada punta porque son un contrato entre dos procesos que
/// se compilan por separado: el agente los llama por su nombre en una cadena, y
/// del lado del servicio los genera zbus a partir del nombre de la función. Un
/// renombre en cualquiera de los dos lados compila perfecto y deja al agente
/// llamando a un método que no existe — o sea, preguntando siempre y sin
/// guardar nada, que se ve exactamente igual que el comportamiento viejo.
///
/// Una prueba del demonio comprueba que la interfaz exporte estos nombres.
pub const PORTAL_DECISION_METHOD: &str = "PortalDecision";
pub const RECORD_PORTAL_DECISION_METHOD: &str = "RecordPortalDecision";

/// Lo que ya se decidió, sin preguntar ni guardar nada.
///
/// Acá por el mismo motivo que los dos de arriba: lo llama un módulo en C
/// —`permisos-de-medios`, en `vasak-wireplumber-modules`— que no comparte
/// nada de este código y lo nombra por una cadena. Un renombre de este lado
/// compila perfecto y deja al módulo llamando a un método que no existe, o sea
/// sin poder leer la política; y como falla cerrando, la cámara se apagaría
/// para todos sin que nada diga por qué.
pub const QUERY_PERMISSION_FOR_METHOD: &str = "QueryPermissionFor";

/// polkit action guarding every change made from the settings interface.
///
/// Without it, any program could call `SetPermission` and grant itself what it
/// was just refused — which would make the whole service decorative.
pub const MANAGE_ACTION: &str = "ar.net.vasak.os.permissions.manage";

/// Services allowed to ask on behalf of somebody else.
///
/// An application does not talk to the permission service directly for an
/// online account — it talks to the account service, which then has to ask. If
/// that second hop asked in its own name, every application would end up
/// sharing one decision recorded against the account service, which is no
/// decision at all.
///
/// So a delegate names the process it is acting for. The list is absolute
/// paths under `/usr/bin`, which needs root to write: a program the user can
/// write cannot be one of these, and therefore cannot claim to be asking for
/// somebody else.
///
/// Estar en la lista no alcanza para hablar por **cualquiera**. La ruta dice qué
/// programa es, no quién lo corre: un delegado que no corre como root sólo
/// puede preguntar por procesos de su propio usuario, y por uno ajeno se le
/// niega sin abrir ningún diálogo. La regla vive en el demonio
/// (`delegate_may_speak_for`) y alcanza a los dos delegados de la sesión,
/// WirePlumber y el sincronizador; el único que habla por todos es el servicio
/// de cuentas, que corre como root.
pub const DELEGATE_BINARIES: [&str; 3] = [
    "/usr/bin/vasak-accounts",
    // El sincronizador de cuentas, que corre como la persona.
    //
    // Es el único dueño del almacén local: escribe lo que baja de los
    // servidores y sirve las lecturas a las aplicaciones. Cuando una de ellas
    // le pide los contactos guardados, la pregunta es sobre **esa** aplicación
    // y no sobre el sincronizador: por eso pregunta en su nombre, con
    // `CheckPermissionFor` y el recurso `store.<área>`. Si preguntara por sí
    // mismo, todas las aplicaciones compartirían una sola decisión anotada
    // contra él, que no es ninguna decisión.
    //
    // Corre sin privilegios, así que sólo puede hablar por procesos de su
    // propio usuario: ver arriba.
    "/usr/bin/vasak-accounts-sync",
    // El módulo `permisos-de-medios` de WirePlumber, que corre dentro de este
    // proceso. Le pregunta a este servicio por cada cliente de PipeWire que se
    // conecta, y nombra al cliente por su pid.
    //
    // No usa `CheckPermissionFor` sino `QueryPermissionFor`: al conectar no hay
    // contexto para preguntarle nada a nadie —«¿le permitís la cámara a
    // pactl?» no es una pregunta que alguien pueda contestar—, así que lee lo
    // ya decidido y no abre diálogo. Quien pregunta con contexto es el portal.
    "/usr/bin/wireplumber",
];

#[cfg(not(debug_assertions))]
pub fn is_delegate(binary_path: &str) -> bool {
    DELEGATE_BINARIES.contains(&binary_path)
}

/// Debug builds also accept a delegate that has not been installed yet, so the
/// chain can be exercised from a working copy. Compiled out of release
/// entirely rather than guarded at runtime.
#[cfg(debug_assertions)]
pub fn is_delegate(binary_path: &str) -> bool {
    if DELEGATE_BINARIES.contains(&binary_path) {
        return true;
    }

    std::env::var_os("VASAK_PERMISSIONS_TEST_ROOT").is_some()
        && DELEGATE_BINARIES.iter().any(|installed| {
            std::path::Path::new(installed).file_name()
                == std::path::Path::new(binary_path).file_name()
        })
}

/// Hasta dónde puede llegar a pedir cada aplicación del sistema.
///
/// ── Qué problema resuelve ───────────────────────────────────────────────────
///
/// Sin esto, el reparto de capacidades entre aplicaciones es una convención y
/// nada más: el gestor de archivos podría pedir `account.email`, y la persona
/// —que confía en el gestor de archivos, porque es del sistema— diría que sí.
/// Bastaría con reemplazar ese binario para llegar al correo con un diálogo que
/// se ve exactamente igual que cualquier otro.
///
/// Con la lista, un programa que pide algo fuera de su alcance **no genera un
/// diálogo**: se le niega y punto. No es una pregunta para la persona — que el
/// gestor de archivos pida el correo no es una decisión que ella tenga que
/// tomar, es un fallo o un ataque.
///
/// ── Qué restringe y qué no ──────────────────────────────────────────────────
///
/// Sólo a los que están en la lista. Un programa que no figura queda como
/// siempre: puede pedir cualquier cosa y la persona decide. No se puede
/// enumerar todo lo que alguien puede instalar, y una lista que negara lo no
/// enumerado dejaría al sistema sin poder correr nada de terceros.
///
/// O sea: esto **acota** a las aplicaciones propias, no **habilita** a nadie.
/// Estar en la lista con un recurso no lo concede — lo sigue decidiendo la
/// persona—; estar en la lista sin él lo impide antes de preguntar.
///
/// ── Por qué está compilada y no en un archivo ───────────────────────────────
///
/// Por lo mismo que [`DELEGATE_BINARIES`]: es un límite de seguridad, no un
/// catálogo. Un archivo en `/etc` lo puede cambiar root, que es quien instala
/// las aplicaciones de todos modos, así que no gana nada; y tenerlo acá deja
/// una sola cosa que auditar, al lado de la otra lista de la misma clase.
///
/// ── Cómo agregar una aplicación ─────────────────────────────────────────────
///
/// Una entrada por binario, con la ruta absoluta bajo `/usr/bin` y los
/// identificadores exactos que devuelve [`Resource::as_id`]. Un test comprueba
/// que cada identificador exista, porque uno mal escrito no falla: no empareja
/// con nada, y el alcance queda más chico de lo que se quiso.
///
/// ── Hacia dónde va ──────────────────────────────────────────────────────────
///
/// Las cuentas en línea van a tener un solo proceso que llegue a la
/// credencial: el sincronizador, que baja el correo, los calendarios y los
/// contactos a un almacén local cifrado. Las aplicaciones van a leer de ahí,
/// con los recursos `store.<área>`, y a medida que cada una migre pierde su
/// `account.<área>` en esta lista y gana el `store.<área>` que le corresponde.
///
/// Todavía no migró ninguna, así que ninguna tiene `store.*`: una prueba lo
/// fija, para que el recurso entre con la migración y no antes.
pub const SCOPED_BINARIES: [(&str, &[&str]); 6] = [
    // Se conecta a discos en la nube —Drive, Nextcloud, OneDrive— y a nada más.
    // No al correo, ni al calendario, ni a los contactos: eso es de las
    // aplicaciones que les corresponden.
    ("/usr/bin/vasak-file-manager", &["account.drive"]),
    // Nada, y no es un descuido.
    //
    // La pantalla de configuración **administra** las cuentas —las agrega, las
    // quita, muestra qué aplicaciones tienen acceso— y no las usa. Los comandos
    // que leían el token de una cuenta estaban registrados sin que nada los
    // llamara, y se quitaron junto con esta línea.
    //
    // Vacío la vuelve el caso más fuerte de la lista: una configuración
    // reemplazada no llega a ningún token, y ni siquiera puede preguntar.
    //
    // Ojo con lo que **no** limita, porque de otra forma esto asustaría: pedir
    // un recurso es una cosa y administrar la política es otra. `ListPermissions`
    // y `SetPermission` no pasan por acá, así que la pantalla sigue pudiendo
    // conceder y quitar permisos de **otros** programas, que es su trabajo. Lo
    // único que no puede es concederse algo a sí misma.
    ("/usr/bin/vasak-settings", &[]),
    // El sincronizador: mantiene al día el correo, los calendarios y los
    // contactos, y los guarda en el almacén local. Corre con la cuenta de la
    // persona, aparte del servicio de cuentas, porque habla con servidores
    // ajenos y eso no puede pasar por un proceso de root.
    //
    // Las tres áreas, y es a propósito: es el proceso que baja lo que después
    // leen las aplicaciones, así que es el que llega a la credencial. La meta
    // es que sea el **único** — hoy el calendario y los contactos todavía
    // piden la suya, hasta que lean del almacén.
    //
    // Nada de `store.*`: el almacén lo sirve él, no lo pide. Y nada fuera de
    // estas tres —ni los discos en la nube, ni los chats—: que viva en el mismo
    // repositorio que el servicio no le da nada, le pide los tokens por el
    // mismo camino que cualquier otra aplicación y este límite lo alcanza igual.
    (
        "/usr/bin/vasak-accounts-sync",
        &["account.email", "account.calendar", "account.contacts"],
    ),
    // El calendario. Hoy lee los eventos por CalDAV de las cuentas conectadas,
    // y por eso conserva `account.calendar`.
    //
    // Es provisorio: cuando lea del almacén cambia `account.calendar` por
    // `store.calendar`, y la credencial queda sólo en el sincronizador. Mientras
    // tanto, nunca los contactos, aunque vivan en el mismo servidor y detrás de
    // la misma contraseña: un servidor Nextcloud entrega las dos cosas con la
    // misma credencial, así que sin esta línea la separación sería una
    // convención y no un límite.
    ("/usr/bin/vasak-calendar", &["account.calendar"]),
    // La aplicación de correo. **Nada**, y es la más expuesta de todas.
    //
    // Lo que muestra lo escribió cualquiera que sepa la dirección de la persona:
    // es la superficie más grande del escritorio. Y a la vez es la que menos
    // tiene para perder, porque no lee el correo — se lo pide ya interpretado a
    // `vasak-accounts-sync`, que sí tiene `account.email` y no dibuja nada.
    //
    // Esta línea es lo que convierte ese reparto en un límite. Sin ella, un
    // `vasak-mail` reemplazado podría pedir `account.email` y la persona vería un
    // diálogo pidiéndole permiso para algo que la aplicación de verdad nunca
    // necesitó — y que si concede, entrega la contraseña de su casilla.
    //
    // Cuando lea del almacén va a ganar `store.email`, que es leer lo que el
    // sincronizador guardó y no llegar a la casilla. `account.email` no lo gana
    // nunca.
    ("/usr/bin/vasak-mail", &[]),
    // La libreta de direcciones. El otro lado de la línea que separa los
    // contactos de los calendarios.
    //
    // Con esta entrada la lista queda simétrica: `vasak-calendar` puede pedir
    // los eventos y no la agenda, y `vasak-contacts` la agenda y no los
    // eventos. Sin las dos, el límite lo tendría sólo una de ellas — y las dos
    // llegan al mismo servidor con la misma contraseña, así que alcanzaba con
    // reemplazar la que no estaba acotada.
    //
    // Provisorio como el del calendario: cuando lea del almacén cambia
    // `account.contacts` por `store.contacts`.
    ("/usr/bin/vasak-contacts", &["account.contacts"]),
];

/// Si `binary_path` puede llegar a pedir `resource_id`.
///
/// Verdadero para todo lo que no esté en la lista: ver arriba por qué.
pub fn may_request(binary_path: &str, resource_id: &str) -> bool {
    match scope_of(binary_path) {
        Some(scope) => scope.contains(&resource_id),
        None => true,
    }
}

/// El alcance declarado de un binario, o `None` si no tiene ninguno.
///
/// En compilaciones de depuración se empareja además por nombre de archivo, para
/// poder ejercitar el límite desde una copia de trabajo sin instalar nada. Queda
/// fuera de release por completo y no detrás de un `if`: emparejar por nombre
/// haría que cualquier `vasak-file-manager` en cualquier carpeta contara como el
/// del sistema, y eso invierte el sentido de la lista.
pub fn scope_of(binary_path: &str) -> Option<&'static [&'static str]> {
    if let Some((_, scope)) = SCOPED_BINARIES
        .iter()
        .find(|(installed, _)| *installed == binary_path)
    {
        return Some(scope);
    }

    #[cfg(debug_assertions)]
    if std::env::var_os("VASAK_PERMISSIONS_TEST_ROOT").is_some() {
        let file_name = std::path::Path::new(binary_path).file_name();
        if let Some((_, scope)) = SCOPED_BINARIES
            .iter()
            .find(|(installed, _)| std::path::Path::new(installed).file_name() == file_name)
        {
            return Some(scope);
        }
    }

    None
}

// ── Identidades del portal ──────────────────────────────────────────────────

/// El prefijo de la clave con la que se guarda lo que se decidió para una
/// aplicación que llegó por el portal de escritorio.
///
/// Las decisiones de este servicio se guardan contra la **ruta del ejecutable**,
/// leída de `/proc` y por lo tanto imposible de falsificar. Por el portal esa
/// identidad no llega: quien llama al backend es `xdg-desktop-portal`, no la
/// aplicación, y lo único que pasa de ella es un `app_id`.
///
/// Son dos espacios de nombres distintos y el prefijo es lo que los mantiene
/// separados. No pueden chocar —una ruta empieza con `/`— y quien lea el
/// archivo de política ve de un vistazo cuáles de las entradas están sostenidas
/// por una identidad verificada y cuáles no.
pub const PORTAL_PREFIX: &str = "portal:";

/// Lo más largo que se acepta como `app_id`.
///
/// No hay límite en la especificación. Existe porque esto termina siendo una
/// clave en un archivo JSON y un renglón en una pantalla, y un identificador de
/// un megabyte no es una aplicación: es alguien probando qué pasa.
const MAX_APP_ID: usize = 255;

/// La clave con la que se guarda lo decidido para una aplicación del portal, o
/// `None` si ese `app_id` no sirve como identidad.
///
/// ── Lo que esta identidad vale, y lo que no ─────────────────────────────────
///
/// El `app_id` lo **declara la propia aplicación**: fuera de un sandbox llega
/// porque el programa llamó a `Register` en `org.freedesktop.host.portal.Registry`
/// de `xdg-desktop-portal`, y nadie comprueba que le corresponda. Un programa
/// puede registrarse como `com.google.Chrome` y heredar lo que Chrome tenga
/// concedido.
///
/// Se usa igual, y la razón es que la alternativa es peor. Sin guardar nada, el
/// portal vuelve a preguntar cada vez —medido: cuatro diálogos idénticos en
/// veinte segundos—, y eso no deja a nadie más seguro: enseña a conceder sin
/// leer, que es la falla que ningún diálogo sobrevive.
///
/// Lo que sí se hace es no disimularlo. Estas entradas quedan como
/// [`Provenance::Unverified`] y se pueden retirar desde Configuración, que es
/// más de lo que hay hoy.
///
/// ── Qué se rechaza ──────────────────────────────────────────────────────────
///
/// Un `app_id` vacío —lo que llega de cualquier programa que no se registró— y
/// cualquiera que lleve algo fuera de letras, dígitos, punto, guion y guion
/// bajo. No es cosmética: sin eso, un `app_id` con una barra o con un `..` se
/// vería como una ruta en el archivo de política y en la pantalla, que es
/// exactamente la confusión que el prefijo existe para evitar.
///
/// Lo rechazado no se guarda y no se lee: se pregunta cada vez, que es lo que
/// pasaba antes de todo esto.
pub fn portal_key(app_id: &str) -> Option<String> {
    if app_id.is_empty() || app_id.len() > MAX_APP_ID {
        return None;
    }

    let aceptable = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
    if !app_id.chars().all(aceptable) {
        return None;
    }

    // Un identificador que empieza o termina en punto, o que lleva dos
    // seguidos, se lee como una ruta relativa en cuanto alguien lo imprima.
    if app_id.starts_with('.') || app_id.ends_with('.') || app_id.contains("..") {
        return None;
    }

    Some(format!("{PORTAL_PREFIX}{app_id}"))
}

/// Si esta clave es una identidad del portal y no la ruta de un ejecutable.
///
/// Lo que cuelga de esta pregunta no es presentación: una identidad del portal
/// no tiene archivo al que enganchar un perfil de AppArmor, así que el camino
/// que escribe excepciones tiene que saltearla.
pub fn is_portal_key(key: &str) -> bool {
    key.starts_with(PORTAL_PREFIX)
}

/// El `app_id` de vuelta, para mostrarlo.
pub fn portal_app_id(key: &str) -> Option<&str> {
    key.strip_prefix(PORTAL_PREFIX)
}

// ── Resources ───────────────────────────────────────────────────────────────

/// Something an application can ask to use.
///
/// Deliberately open-ended: hardware and online accounts share one model, so a
/// new resource is a new variant and everything else — storage, the dialog, the
/// settings list — already handles it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Resource {
    Camera,
    Microphone,
    /// Recording or capturing the screen.
    ScreenCapture,
    Location,
    /// Reading the keyboard globally: keyloggers and global shortcuts alike.
    InputCapture,
    /// Reading the files that prove who you are: SSH and GPG keys, the
    /// keyring's database, the tokens under `~/.config` that log you into
    /// things.
    ///
    /// Grouped into one decision on purpose. Splitting them would ask the
    /// person a question they cannot answer usefully — nobody trusts a program
    /// with their GPG key but not their SSH key — and each extra switch makes
    /// the list longer without making anyone safer.
    Credentials,
    /// Access to one capability of the user's online accounts.
    #[serde(rename = "account")]
    Account(AccountResource),
    /// Leer lo que el sincronizador ya guardó de un área, en el almacén local.
    ///
    /// Es otra pregunta que [`Resource::Account`], y la diferencia es la que
    /// importa. `account.calendar` llega a la **credencial**: con él se pide el
    /// token de la cuenta, y en un servidor como Nextcloud esa contraseña abre
    /// todo —el calendario, los contactos, los archivos—. `store.calendar` sólo
    /// deja leer los eventos que el sincronizador ya bajó, y no le da a la
    /// aplicación forma de llegar al servidor.
    ///
    /// Un solo recurso por área, de lectura: dos diálogos casi iguales
    /// —«ver tus eventos» y «ver y cambiar tus eventos»— confunden más de lo
    /// que protegen.
    #[serde(rename = "store")]
    Store(StoreResource),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountResource {
    Email,
    Calendar,
    Contacts,
    Chat,
    Drive,
    Tasks,
}

/// Las áreas del almacén local que se pueden leer.
///
/// Son tres y no las seis de [`AccountResource`] porque son las que el
/// sincronizador guarda. Los chats, los discos en la nube y las tareas de las
/// APIs propias de cada proveedor no pasan por el almacén; las tareas de
/// CalDAV viajan con el calendario, que es donde las guarda el servidor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoreResource {
    Email,
    Calendar,
    Contacts,
}

impl Resource {
    /// Whether refusing this actually stops anything.
    ///
    /// Online accounts are handed out by a service that asks before answering,
    /// so a refusal is enforced.
    ///
    /// The camera and the microphone are now **partly** enforced, which is why
    /// this still answers no for them. An AppArmor profile denies the device
    /// nodes to applications the system did not install, and this service
    /// writes a per-application exception when somebody allows one. But that
    /// only covers the direct route: a program that asks PipeWire instead of
    /// opening the device — which is what modern applications do — is still not
    /// stopped, and neither is a program no profile covers, such as anything
    /// the package manager installed.
    ///
    /// Saying yes here would overstate it. Whoever asks this question wants to
    /// know whether a refusal can be relied upon, and for those two it cannot
    /// be yet.
    ///
    /// The screen, the location and the keyboard are handed out by PipeWire and
    /// the desktop portal, and neither consults this policy: a program that
    /// goes straight to them is not stopped, and the portal cannot even say
    /// which program is asking — the identity it passes on is empty for
    /// anything outside a sandbox.
    ///
    /// This is *not* the question the service asks before storing a decision —
    /// that one is [`Self::decision_has_effect`], and confusing the two is what
    /// left the camera switch unable to move. The camera is not enforceable,
    /// because the PipeWire path is still open; but deciding it does have an
    /// effect, because an AppArmor exception gets written either way. What is
    /// refused outright is a decision that changes *nothing at all*: the person
    /// could neither rely on it nor take it back.
    ///
    /// Lo guardado en el almacén local (`store.*`) tampoco, y por un motivo
    /// parecido al de la cámara. El sincronizador pregunta antes de servir una
    /// lectura, pero la base es un archivo de la persona y su clave vive en el
    /// llavero de la sesión, que le entrega sus secretos a cualquier proceso de
    /// ese mismo usuario. Un programa que no quiera preguntar puede ir directo
    /// al archivo. El permiso es consentimiento y visibilidad, no una frontera,
    /// y decir otra cosa acá sería prometer lo que no se cumple.
    pub fn is_enforceable(&self) -> bool {
        matches!(self, Resource::Account(_))
    }

    /// Whether deciding this changes anything at all.
    ///
    /// A different question from [`Self::is_enforceable`], and mixing the two
    /// kept the camera switch from working: that one asks whether a refusal can
    /// be *relied upon*, and for the camera it cannot yet, because a program can
    /// still ask PipeWire. This one asks whether the decision has any effect —
    /// and it does: the service writes an AppArmor exception, so allowing gives
    /// a confined application access it did not have, and removing takes it
    /// away.
    ///
    /// Storing a decision that changes nothing would be worse than refusing it,
    /// which is why the distinction exists at all. But refusing one that *does*
    /// change something leaves a switch that cannot be moved.
    pub fn decision_has_effect(&self) -> bool {
        // `store.*` cambia algo: el sincronizador consulta la decisión antes de
        // servir cada lectura, así que negar corta ese camino y permitir lo
        // abre. Que haya otro camino es lo que dice `is_enforceable`.
        matches!(
            self,
            Resource::Account(_)
                | Resource::Store(_)
                | Resource::Camera
                | Resource::Microphone
                | Resource::Credentials
        )
    }

    /// Lo mismo, pero para la identidad contra la que se va a guardar.
    ///
    /// Hacía falta partirlo porque la respuesta dejó de ser la misma para las
    /// dos clases de identidad que este servicio maneja, y dar una sola
    /// habilitaría interruptores muertos en la mitad de los casos.
    ///
    /// Contra la **ruta de un ejecutable** vale lo de siempre: lo que cambia
    /// algo es lo que un perfil de AppArmor niega, más las cuentas.
    ///
    /// Contra una **identidad del portal** son otros dos, y no se superponen
    /// del todo. La cámara y la captura de pantalla las pregunta el portal, y
    /// desde que el backend consulta lo guardado antes de abrir el diálogo,
    /// decidirlas cambia lo que pasa la próxima vez. El micrófono y las
    /// credenciales no: por el portal no llega ninguna de las dos, así que
    /// guardar una decisión sobre ellas dejaría un interruptor que no mueve
    /// nada. Las cuentas tampoco — ésas no pasan por el portal en absoluto.
    pub fn decision_has_effect_for(&self, key: &str) -> bool {
        if is_portal_key(key) {
            return matches!(self, Resource::Camera | Resource::ScreenCapture);
        }
        self.decision_has_effect()
    }

    /// Stable text form used on the bus and in the stored policy.
    ///
    /// Spelled out by hand rather than derived, because these strings end up in
    /// a file on disk: a refactor that renamed a variant would otherwise
    /// silently invalidate every decision the user had already made.
    pub fn as_id(&self) -> String {
        match self {
            Resource::Camera => "camera".into(),
            Resource::Microphone => "microphone".into(),
            Resource::ScreenCapture => "screen-capture".into(),
            Resource::Location => "location".into(),
            Resource::InputCapture => "input-capture".into(),
            Resource::Credentials => "credentials".into(),
            Resource::Account(capability) => format!("account.{}", capability.as_id()),
            Resource::Store(area) => format!("store.{}", area.as_id()),
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        if let Some(capability) = id.strip_prefix("account.") {
            return AccountResource::from_id(capability).map(Resource::Account);
        }
        if let Some(area) = id.strip_prefix("store.") {
            return StoreResource::from_id(area).map(Resource::Store);
        }

        match id {
            "camera" => Some(Resource::Camera),
            "microphone" => Some(Resource::Microphone),
            "screen-capture" => Some(Resource::ScreenCapture),
            "location" => Some(Resource::Location),
            "input-capture" => Some(Resource::InputCapture),
            "credentials" => Some(Resource::Credentials),
            _ => None,
        }
    }
}

impl AccountResource {
    /// Todas, por lo mismo que [`StoreResource::ALL`].
    pub const ALL: [AccountResource; 6] = [
        AccountResource::Email,
        AccountResource::Calendar,
        AccountResource::Contacts,
        AccountResource::Chat,
        AccountResource::Drive,
        AccountResource::Tasks,
    ];

    pub fn as_id(&self) -> &'static str {
        match self {
            AccountResource::Email => "email",
            AccountResource::Calendar => "calendar",
            AccountResource::Contacts => "contacts",
            AccountResource::Chat => "chat",
            AccountResource::Drive => "drive",
            AccountResource::Tasks => "tasks",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "email" => Some(AccountResource::Email),
            "calendar" => Some(AccountResource::Calendar),
            "contacts" => Some(AccountResource::Contacts),
            "chat" => Some(AccountResource::Chat),
            "drive" => Some(AccountResource::Drive),
            "tasks" => Some(AccountResource::Tasks),
            _ => None,
        }
    }
}

impl StoreResource {
    /// Todas, para que quien tenga que cubrirlas —los catálogos de idioma, la
    /// pantalla de Configuración— las recorra sin copiar la lista.
    pub const ALL: [StoreResource; 3] = [
        StoreResource::Email,
        StoreResource::Calendar,
        StoreResource::Contacts,
    ];

    /// Escritas a mano por lo mismo que las de [`Resource::as_id`]: terminan en
    /// un archivo en disco.
    pub fn as_id(&self) -> &'static str {
        match self {
            StoreResource::Email => "email",
            StoreResource::Calendar => "calendar",
            StoreResource::Contacts => "contacts",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "email" => Some(StoreResource::Email),
            "calendar" => Some(StoreResource::Calendar),
            "contacts" => Some(StoreResource::Contacts),
            _ => None,
        }
    }
}

// ── Decisions ───────────────────────────────────────────────────────────────

/// What the stored policy says about one application and one resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Allowed,
    Denied,
    /// Never decided, so the user has to be asked.
    Unknown,
}

impl Decision {
    pub fn from_answer(allowed: bool) -> Self {
        if allowed {
            Decision::Allowed
        } else {
            Decision::Denied
        }
    }

    pub fn is_allowed(self) -> bool {
        matches!(self, Decision::Allowed)
    }

    /// La forma en texto que viaja por el bus.
    ///
    /// Escrita a mano, como la de los recursos y por lo mismo: estas tres
    /// cadenas son un contrato entre el servicio y el agente, y derivarlas de
    /// los nombres de las variantes dejaría que un cambio de nombre las moviera
    /// sin que nada se queje.
    pub fn as_id(self) -> &'static str {
        match self {
            Decision::Allowed => "allowed",
            Decision::Denied => "denied",
            Decision::Unknown => "unknown",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "allowed" => Some(Decision::Allowed),
            "denied" => Some(Decision::Denied),
            "unknown" => Some(Decision::Unknown),
            _ => None,
        }
    }
}

// ── Applications ────────────────────────────────────────────────────────────

/// How much the service can vouch for the identity of a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provenance {
    /// Installed under a path only root can write, so the binary behind a
    /// remembered decision cannot have been swapped for another one.
    SystemInstalled,
    /// Anywhere the user can write: their own scripts, a downloaded AppImage.
    /// The decision is still honoured, but the dialog says so — the same thing
    /// macOS means by an unidentified developer.
    Unverified,
}

/// A program asking for something, as the service sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    /// Absolute, symlink-resolved path to the executable. This is the identity
    /// a decision is recorded against.
    pub binary_path: String,
    /// Name to show a person, resolved from the desktop entry when there is
    /// one and falling back to the file name.
    pub display_name: String,
    pub provenance: Provenance,
}

/// One stored decision, as listed by the settings interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEntry {
    /// Si este programa **nos pregunta** antes de usar el recurso.
    ///
    /// Separa las dos formas en que una decisión llega a hacerse cumplir, que
    /// la procedencia sola no distingue:
    ///
    /// - Un programa que el sistema no instaló se confina con un perfil, y
    ///   permitirle algo le escribe una excepción. Ahí lo hace cumplir el
    ///   kernel, sin que el programa colabore.
    /// - Un programa del sistema como `vasak-connect` no tiene perfil que lo
    ///   limite, pero **consulta** antes de encender la cámara del teléfono y
    ///   respeta la respuesta. Su decisión se hace cumplir igual.
    ///
    /// Sin esta distinción, la pantalla apagaba el interruptor de todo lo que
    /// vino con el sistema —correcto para lo primero, y para lo segundo dejaba
    /// un permiso concedido que no había forma de retirar.
    #[serde(default)]
    pub asks: bool,
    pub application: Application,
    /// Resource ids (`Resource::as_id`) mapped to what was decided.
    pub decisions: std::collections::BTreeMap<String, Decision>,
}

/// What the agent is asked to put to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub application: Application,
    pub resource_id: String,
    /// Extra context for account resources: which account is being asked for.
    /// For a generic file block, the path that was denied. Empty otherwise.
    pub detail: String,
    /// El perfil de AppArmor que produjo el bloqueo, cuando lo hubo.
    ///
    /// Hace falta para poder **decidir desde el aviso**: permitir un bloqueo
    /// genérico se pide como `AllowBlocked(perfil, ruta)`, y sin el perfil el
    /// aviso sólo puede contar lo que pasó y mandar a Configuración.
    ///
    /// Con `default` para que un agente viejo y un servicio nuevo se sigan
    /// entendiendo: el campo llega vacío y el aviso se comporta como antes.
    #[serde(default)]
    pub profile: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These strings are written to disk. If a rename ever changes one, every
    /// decision recorded under the old spelling silently stops matching and
    /// the user is asked all over again.
    #[test]
    fn resource_ids_survive_a_round_trip() {
        let resources = [
            Resource::Camera,
            Resource::Microphone,
            Resource::ScreenCapture,
            Resource::Location,
            Resource::InputCapture,
            Resource::Account(AccountResource::Email),
            Resource::Account(AccountResource::Calendar),
            Resource::Account(AccountResource::Contacts),
            Resource::Account(AccountResource::Chat),
            Resource::Account(AccountResource::Drive),
            Resource::Account(AccountResource::Tasks),
            Resource::Store(StoreResource::Email),
            Resource::Store(StoreResource::Calendar),
            Resource::Store(StoreResource::Contacts),
        ];

        for resource in resources {
            let id = resource.as_id();
            assert_eq!(
                Resource::from_id(&id),
                Some(resource.clone()),
                "id {id} did not round-trip"
            );
        }
    }

    #[test]
    fn the_ids_are_the_ones_written_to_disk() {
        assert_eq!(Resource::Camera.as_id(), "camera");
        assert_eq!(Resource::ScreenCapture.as_id(), "screen-capture");
        assert_eq!(
            Resource::Account(AccountResource::Email).as_id(),
            "account.email"
        );
    }

    /// Los tres del almacén, con el texto exacto que va a quedar en disco y el
    /// que el sincronizador va a mandar por el bus.
    #[test]
    fn los_recursos_del_almacen_se_reconocen() {
        for (id, area) in [
            ("store.email", StoreResource::Email),
            ("store.calendar", StoreResource::Calendar),
            ("store.contacts", StoreResource::Contacts),
        ] {
            let resource = Resource::from_id(id).unwrap_or_else(|| panic!("{id} no se reconoce"));
            assert_eq!(resource, Resource::Store(area));
            assert_eq!(resource.as_id(), id, "{id} no vuelve igual");
        }

        // Y `ALL` es exactamente esos tres: quien recorra la lista para cubrir
        // los catálogos de idioma no se puede saltear ninguno.
        let ids: Vec<String> = StoreResource::ALL
            .iter()
            .map(|area| Resource::Store(area.clone()).as_id())
            .collect();
        assert_eq!(ids, ["store.email", "store.calendar", "store.contacts"]);
    }

    /// Un área inventada no se adivina. `store.drive` es el caso que importa:
    /// `drive` sí es una capacidad de las cuentas, pero el almacén no la
    /// guarda, y aceptarla dejaría un interruptor que no lee nada.
    #[test]
    fn un_area_del_almacen_inventada_se_rechaza() {
        for id in [
            "store.algo",
            "store.drive",
            "store.chat",
            "store.tasks",
            "store.",
            "store",
            "store.Email",
            "store.email.extra",
        ] {
            assert_eq!(Resource::from_id(id), None, "{id} no tenía que reconocerse");
        }
    }

    /// Leer lo guardado y llegar a la credencial son recursos distintos: una
    /// decisión sobre uno nunca puede leerse como decisión sobre el otro.
    #[test]
    fn leer_el_almacen_no_es_llegar_a_la_cuenta() {
        for area in StoreResource::ALL {
            let store = Resource::Store(area.clone()).as_id();
            let account = format!("account.{}", area.as_id());
            assert_ne!(store, account);
            assert_ne!(Resource::from_id(&store), Resource::from_id(&account));
        }
    }

    #[test]
    fn an_unknown_id_is_rejected_rather_than_guessed() {
        assert_eq!(Resource::from_id("nonsense"), None);
        assert_eq!(Resource::from_id("account.nonsense"), None);
        assert_eq!(Resource::from_id("account."), None);
        assert_eq!(Resource::from_id(""), None);
    }
}

#[cfg(test)]
mod delegate_tests {
    use super::*;

    #[test]
    fn only_services_installed_by_the_system_may_ask_for_someone_else() {
        assert!(is_delegate("/usr/bin/vasak-accounts"));
        assert!(is_delegate("/usr/bin/vasak-accounts-sync"));
        assert!(is_delegate("/usr/bin/wireplumber"));

        // A program the user can write must never be able to claim it is
        // asking on another program's behalf — it would name whichever
        // already-approved program it liked.
        assert!(!is_delegate("/home/someone/.local/bin/vasak-accounts"));
        assert!(!is_delegate("/tmp/vasak-accounts"));
        assert!(!is_delegate("vasak-accounts"));
        assert!(!is_delegate("/usr/bin/anything-else"));
        assert!(!is_delegate("/home/someone/.local/bin/wireplumber"));
        assert!(!is_delegate("/home/someone/.local/bin/vasak-accounts-sync"));
        assert!(!is_delegate("/usr/local/bin/vasak-accounts-sync"));
    }

    /// Un delegado de más es un programa que puede hablar por cualquier otro,
    /// así que la lista se cuenta: si crece sin que nadie lo note, esto falla y
    /// obliga a mirar por qué.
    #[test]
    fn la_lista_de_delegados_no_crece_sola() {
        assert_eq!(
            DELEGATE_BINARIES.len(),
            3,
            "agregar un delegado es dejar que un programa hable por otro: \
             que sea a propósito"
        );
        for delegate in DELEGATE_BINARIES {
            assert!(
                delegate.starts_with("/usr/bin/"),
                "{delegate} no está bajo /usr/bin, así que el usuario podría \
                 escribirlo y hacerse pasar por él"
            );
        }
    }
}

#[cfg(test)]
mod enforcement_tests {
    use super::*;

    /// The list has to match what the service actually stands behind. If a
    /// resource starts being enforced, this is the one place to change.
    /// La cámara y el micrófono: decidirlos cambia algo aunque la garantía no
    /// sea completa todavía. Confundir las dos preguntas dejó el interruptor
    /// sin poder moverse.
    #[test]
    fn deciding_the_camera_now_has_an_effect() {
        assert!(Resource::Camera.decision_has_effect());
        assert!(Resource::Microphone.decision_has_effect());
        assert!(Resource::Account(AccountResource::Email).decision_has_effect());
    }

    /// Y lo que sigue sin control no: guardar una decisión que no cambia nada
    /// es peor que no aceptarla.
    #[test]
    fn deciding_what_nothing_enforces_still_has_none() {
        assert!(!Resource::ScreenCapture.decision_has_effect());
        assert!(!Resource::Location.decision_has_effect());
        assert!(!Resource::InputCapture.decision_has_effect());
    }

    #[test]
    fn only_online_accounts_are_enforced_today() {
        assert!(Resource::Account(AccountResource::Email).is_enforceable());
        assert!(Resource::Account(AccountResource::Drive).is_enforceable());

        // Handed out by PipeWire and the desktop portal, which do not consult
        // this policy — and the portal cannot say which program is asking.
        assert!(!Resource::Camera.is_enforceable());
        assert!(!Resource::Microphone.is_enforceable());
        assert!(!Resource::ScreenCapture.is_enforceable());
        assert!(!Resource::Location.is_enforceable());
        assert!(!Resource::InputCapture.is_enforceable());
    }

    /// Lo guardado en el almacén: decidirlo cambia algo —el sincronizador lo
    /// consulta antes de servir cada lectura— pero un rechazo no es una
    /// frontera, porque la base y su clave están al alcance de cualquier
    /// proceso de la misma persona. Las dos respuestas tienen que decir eso.
    #[test]
    fn el_almacen_se_decide_pero_no_es_una_frontera() {
        for area in StoreResource::ALL {
            let resource = Resource::Store(area);
            assert!(resource.decision_has_effect(), "{}", resource.as_id());
            assert!(
                resource.decision_has_effect_for("/usr/bin/vasak-contacts"),
                "{}",
                resource.as_id()
            );
            assert!(!resource.is_enforceable(), "{}", resource.as_id());
        }
    }

    /// Por el portal no llega ninguna lectura del almacén, así que una decisión
    /// anotada contra una identidad del portal no movería nada.
    #[test]
    fn el_almacen_no_se_decide_por_el_portal() {
        let key = portal_key("com.google.Chrome").expect("identidad válida");
        for area in StoreResource::ALL {
            assert!(!Resource::Store(area).decision_has_effect_for(&key));
        }
    }
}

#[cfg(test)]
mod policy_tests {
    /// La política de D-Bus tiene que dejar al servicio hablarle al agente.
    ///
    /// Sin esa regla el servicio no puede llamarlo —en el bus del sistema los
    /// method calls se deniegan por omisión— y se cae el flujo entero de
    /// preguntar, en silencio y sin que nada deje de compilar. Fue exactamente
    /// lo que pasó: el diálogo de permisos nunca llegaba a aparecer.
    ///
    /// Se comprueba contra el archivo que se instala, y usando la constante,
    /// para que renombrar la interfaz acá haga fallar la prueba en vez de
    /// romper el sistema en silencio.
    #[test]
    fn the_bus_policy_lets_the_service_reach_the_agent() {
        let policy = include_str!("../../packaging/ar.net.vasak.os.Permissions.conf");
        let rule = format!("<allow send_interface=\"{}\"/>", super::AGENT_INTERFACE);
        assert!(
            policy.contains(&rule),
            "la política instalada no deja al servicio llamar al agente; \
             falta la regla: {rule}"
        );
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    /// El caso que motivó la lista: el gestor de archivos llega a los discos en
    /// la nube y a nada más.
    #[test]
    fn el_gestor_de_archivos_solo_llega_a_los_discos_en_la_nube() {
        let gestor = "/usr/bin/vasak-file-manager";

        assert!(may_request(gestor, "account.drive"));

        for prohibido in [
            "account.email",
            "account.calendar",
            "account.contacts",
            "account.chat",
            "account.tasks",
            "camera",
            "microphone",
            "credentials",
        ] {
            assert!(
                !may_request(gestor, prohibido),
                "el gestor de archivos no tenía que poder pedir '{prohibido}'"
            );
        }
    }

    /// La lista **acota** a las aplicaciones propias, no habilita a nadie. Un
    /// programa que no figura queda como siempre: pide, y la persona decide.
    ///
    /// Sin esta propiedad el sistema no podría correr nada de terceros, porque
    /// no se puede enumerar todo lo que alguien instala.
    #[test]
    fn un_programa_que_no_figura_puede_pedir_cualquier_cosa() {
        for ajeno in [
            "/usr/bin/thunderbird",
            "/usr/bin/evolution",
            "/home/alguien/.local/bin/algo",
            "",
        ] {
            assert!(may_request(ajeno, "account.email"), "{ajeno}");
            assert!(may_request(ajeno, "camera"), "{ajeno}");
            assert_eq!(scope_of(ajeno), None, "{ajeno} no debería tener alcance");
        }
    }

    /// El sincronizador llega al correo, al calendario y a los contactos, y a
    /// nada más.
    ///
    /// Antes sólo llegaba al correo y esta prueba exigía que no pudiera pedir
    /// el calendario ni los contactos. Se invirtió a propósito: es el proceso
    /// que baja las tres áreas al almacén local, y la meta es que sea el único
    /// que llegue a la credencial.
    ///
    /// Sigue acotado, y eso es lo que la prueba cuida del otro lado: ni los
    /// discos en la nube, ni los chats, ni el almacén que él mismo sirve.
    #[test]
    fn el_sincronizador_llega_al_correo_al_calendario_y_a_los_contactos() {
        let sync = "/usr/bin/vasak-accounts-sync";

        for allowed in ["account.email", "account.calendar", "account.contacts"] {
            assert!(
                may_request(sync, allowed),
                "tenía que poder pedir '{allowed}'"
            );
        }
        for forbidden in [
            "account.drive",
            "account.chat",
            "account.tasks",
            "store.email",
            "store.calendar",
            "store.contacts",
            "credentials",
            "camera",
        ] {
            assert!(
                !may_request(sync, forbidden),
                "no tenía que poder pedir '{forbidden}'"
            );
        }
    }

    /// Ninguna aplicación tiene `store.*` todavía.
    ///
    /// El recurso entra en el alcance de cada una cuando migre a leer del
    /// almacén, en el mismo cambio que le saca su `account.*`. Antes no: una
    /// aplicación con los dos llegaría a la credencial **y** a lo guardado, y
    /// el reparto quedaría peor que hoy.
    #[test]
    fn ninguna_aplicacion_tiene_el_almacen_todavia() {
        for (binary, scope) in SCOPED_BINARIES {
            for id in scope {
                assert!(
                    !id.starts_with("store."),
                    "{binary} tiene '{id}' antes de haber migrado al almacén"
                );
            }
        }
    }

    /// El calendario conserva su `account.calendar` hasta migrar: sacárselo
    /// antes lo dejaría sin eventos, porque todavía no lee del almacén.
    #[test]
    fn el_calendario_conserva_su_cuenta_hasta_migrar() {
        assert_eq!(
            scope_of("/usr/bin/vasak-calendar"),
            Some(&["account.calendar"][..])
        );
    }

    /// El calendario llega al calendario y a nada más.
    ///
    /// Los contactos son el caso que importa: viven en el mismo servidor y
    /// detrás de la misma contraseña que los calendarios, así que sin esta línea
    /// la separación entre las dos aplicaciones sería una convención y no un
    /// límite.
    #[test]
    fn el_calendario_no_llega_a_los_contactos() {
        let calendario = "/usr/bin/vasak-calendar";

        assert!(may_request(calendario, "account.calendar"));
        for prohibido in [
            "account.contacts",
            "account.email",
            "account.drive",
            "account.chat",
            "account.tasks",
            "credentials",
        ] {
            assert!(
                !may_request(calendario, prohibido),
                "no tenía que poder pedir '{prohibido}'"
            );
        }
    }

    /// El otro lado de la línea que separa los contactos de los calendarios.
    ///
    /// Con las dos entradas la lista queda simétrica: el calendario llega a los
    /// eventos y no a la agenda, y la agenda a los contactos y no a los
    /// eventos. Con una sola, alcanzaba con reemplazar la aplicación que no
    /// estaba acotada — las dos llegan al mismo servidor con la misma
    /// contraseña.
    #[test]
    fn los_contactos_no_llegan_al_calendario() {
        let contactos = "/usr/bin/vasak-contacts";

        assert!(may_request(contactos, "account.contacts"));
        for prohibido in [
            "account.calendar",
            "account.email",
            "account.drive",
            "account.chat",
            "account.tasks",
            "credentials",
        ] {
            assert!(
                !may_request(contactos, prohibido),
                "no tenía que poder pedir '{prohibido}'"
            );
        }
    }

    /// La aplicación de correo tampoco puede pedir nada, y es el caso que más
    /// se gana.
    ///
    /// Es la más expuesta del escritorio —lo que muestra lo escribió cualquiera
    /// que sepa la dirección de la persona— y no lee el correo: se lo pide ya
    /// interpretado al sincronizador. Sin esta línea, una copia reemplazada
    /// podría pedir `account.email` y la persona vería un diálogo pidiéndole
    /// permiso para algo que la aplicación de verdad nunca necesitó.
    #[test]
    fn el_correo_no_puede_pedir_ni_el_correo() {
        let mail_app = "/usr/bin/vasak-mail";

        assert_eq!(scope_of(mail_app), Some(&[][..]));
        for resource in [
            "account.email",
            "account.contacts",
            "account.calendar",
            "account.drive",
            // Tampoco lo guardado, hasta que migre a leer del almacén.
            "store.email",
            "credentials",
        ] {
            assert!(
                !may_request(mail_app, resource),
                "no tenía que poder pedir '{resource}'"
            );
        }
    }

    /// El primero de los dos alcances vacíos, que son el caso más fuerte.
    ///
    /// La pantalla de configuración administra las cuentas y no las usa, así que
    /// no puede pedir **nada**. Una configuración reemplazada no llega a ningún
    /// token y ni siquiera puede preguntar.
    #[test]
    fn configuracion_no_puede_pedir_nada() {
        let configuracion = "/usr/bin/vasak-settings";

        assert_eq!(scope_of(configuracion), Some(&[][..]));
        for recurso in [
            "account.email",
            "account.drive",
            "account.calendar",
            "camera",
            "microphone",
            "credentials",
        ] {
            assert!(
                !may_request(configuracion, recurso),
                "configuración no tenía que poder pedir '{recurso}'"
            );
        }
    }

    /// Y lo que el alcance vacío **no** limita, que es lo que hace que no rompa
    /// la pantalla: pedir un recurso es una cosa y administrar la política es
    /// otra. `ListPermissions` y `SetPermission` no consultan esta lista contra
    /// quien llama, sino contra el programa que se está administrando.
    ///
    /// El test vive acá porque el riesgo es que alguien lea «alcance vacío» y
    /// crea que la configuración quedó sin poder hacer su trabajo.
    #[test]
    fn el_alcance_vacio_no_le_impide_administrar_a_otros() {
        // Administrar al gestor de archivos dentro de su alcance sigue siendo
        // posible: lo que se consulta es el binario administrado, no el que
        // administra.
        assert!(may_request("/usr/bin/vasak-file-manager", "account.drive"));
        // Y a un programa de terceros, cualquier cosa.
        assert!(may_request("/usr/bin/thunderbird", "account.email"));
    }

    /// Estar en la lista con un recurso no lo concede: lo sigue decidiendo la
    /// persona. Lo único que hace la lista es impedir lo que no está.
    #[test]
    fn tener_alcance_no_es_tener_permiso() {
        // `may_request` habla de lo que se puede *pedir*. El sí o el no lo
        // sigue dando la política del usuario, que es otro archivo y otro
        // camino: este test está acá para que nadie confunda las dos cosas al
        // leer la lista.
        assert!(may_request("/usr/bin/vasak-file-manager", "account.drive"));
        assert_eq!(
            scope_of("/usr/bin/vasak-file-manager"),
            Some(&["account.drive"][..]),
        );
    }

    /// Un identificador mal escrito en la lista no falla: no empareja con nada,
    /// y el alcance queda más chico de lo que se quiso — o sea, la aplicación
    /// deja de andar sin que nadie sepa por qué. Por eso se comprueba que cada
    /// uno exista de verdad.
    #[test]
    fn todos_los_recursos_de_la_lista_existen() {
        for (binario, alcance) in SCOPED_BINARIES {
            for id in alcance {
                let recurso = Resource::from_id(id);
                assert!(
                    recurso.is_some(),
                    "'{id}' del alcance de {binario} no es un recurso conocido"
                );
                // Y de ida y vuelta, para que el identificador escrito a mano
                // sea exactamente el que el servicio usa en el bus y en disco.
                assert_eq!(
                    recurso.unwrap().as_id(),
                    *id,
                    "'{id}' no es la forma canónica del recurso"
                );
            }
        }
    }

    /// Las rutas son absolutas y bajo `/usr/bin`, que necesita root para
    /// escribir. Una ruta que el usuario pueda escribir haría que la lista
    /// acotara a un programa que él mismo puede reemplazar, lo que no acota
    /// nada.
    #[test]
    fn las_rutas_de_la_lista_estan_donde_solo_root_escribe() {
        for (binario, _) in SCOPED_BINARIES {
            assert!(
                binario.starts_with("/usr/bin/"),
                "{binario} no está en /usr/bin"
            );
        }
    }

    /// Sin duplicados: dos entradas para el mismo binario harían que el alcance
    /// dependiera de cuál se encuentra primero.
    #[test]
    fn no_hay_binarios_repetidos_en_la_lista() {
        let mut vistos = std::collections::BTreeSet::new();
        for (binario, _) in SCOPED_BINARIES {
            assert!(vistos.insert(binario), "{binario} está dos veces");
        }
    }
}

#[cfg(test)]
mod tests_portal {
    use super::*;

    /// El caso real, medido en el diario del agente.
    #[test]
    fn un_app_id_de_verdad_sirve_como_identidad() {
        assert_eq!(
            portal_key("com.google.Chrome").as_deref(),
            Some("portal:com.google.Chrome")
        );
        assert_eq!(
            portal_key("org.gnome.Calculator").as_deref(),
            Some("portal:org.gnome.Calculator")
        );
    }

    /// Vacío es lo que llega de todo programa que no se registró, y es la mitad
    /// de los casos. No es un error: es que no hay identidad, y sin identidad no
    /// se guarda nada.
    #[test]
    fn sin_app_id_no_hay_identidad() {
        assert_eq!(portal_key(""), None);
    }

    /// Lo que no se acepta, y el motivo de cada uno.
    ///
    /// Todos terminan en lo mismo: una clave que, impresa en el archivo de
    /// política o en la pantalla, se leería como otra cosa. El prefijo separa
    /// los dos espacios de nombres y esto es lo que impide volver a juntarlos
    /// por la puerta de atrás.
    #[test]
    fn lo_que_se_leeria_como_una_ruta_se_rechaza() {
        // Una barra lo haría parecer una ruta adentro del espacio del portal.
        assert_eq!(portal_key("com.google/Chrome"), None);
        assert_eq!(portal_key("/usr/bin/vasak-settings"), None);
        // `..` es lo que convierte un nombre en un recorrido.
        assert_eq!(portal_key("com..google"), None);
        assert_eq!(portal_key(".."), None);
        assert_eq!(portal_key("."), None);
        assert_eq!(portal_key(".oculto"), None);
        assert_eq!(portal_key("termina.en.punto."), None);
        // Un salto de línea partiría en dos cualquier registro que la imprima.
        assert_eq!(portal_key("com.google\nChrome"), None);
        assert_eq!(portal_key("con espacio"), None);
        // Y lo que se ve igual sin serlo: una `а` cirílica no es una `a`.
        assert_eq!(portal_key("com.google.Chrome\u{0430}"), None);
    }

    /// Nada desmedido, aunque sea legal carácter por carácter.
    #[test]
    fn un_app_id_desmedido_se_rechaza() {
        let largo = "a".repeat(MAX_APP_ID + 1);
        assert_eq!(portal_key(&largo), None);
        // Justo en el límite sí entra: el corte tiene que estar donde dice.
        assert!(portal_key(&"a".repeat(MAX_APP_ID)).is_some());
    }

    /// Los dos espacios de nombres no se pueden tocar.
    ///
    /// Es la propiedad de la que cuelga todo lo demás: si una identidad del
    /// portal pudiera escribirse igual que la ruta de un ejecutable, una
    /// aplicación que se registre con el nombre adecuado heredaría lo que se
    /// decidió para un binario del sistema.
    #[test]
    fn una_identidad_del_portal_nunca_es_una_ruta() {
        for app_id in ["com.google.Chrome", "usr.bin.vasak-settings", "a"] {
            let key = portal_key(app_id).expect("identidad válida");
            assert!(!key.starts_with('/'), "{key}");
            assert!(is_portal_key(&key), "{key}");
            assert_eq!(portal_app_id(&key), Some(app_id));
        }
    }

    /// Y al revés: una ruta no se confunde con una identidad del portal.
    #[test]
    fn una_ruta_no_es_una_identidad_del_portal() {
        assert!(!is_portal_key("/usr/bin/vasak-settings"));
        assert_eq!(portal_app_id("/usr/bin/vasak-settings"), None);
    }

    /// Por el portal llegan dos recursos, y sólo esos dos se guardan.
    ///
    /// Anotar el micrófono o las credenciales contra una identidad del portal
    /// dejaría un interruptor en Configuración que no mueve nada: por ese camino
    /// no llega ninguno de los dos.
    #[test]
    fn por_el_portal_solo_cuentan_la_camara_y_la_pantalla() {
        let key = portal_key("com.google.Chrome").expect("identidad válida");

        assert!(Resource::Camera.decision_has_effect_for(&key));
        assert!(Resource::ScreenCapture.decision_has_effect_for(&key));

        assert!(!Resource::Microphone.decision_has_effect_for(&key));
        assert!(!Resource::Credentials.decision_has_effect_for(&key));
        assert!(!Resource::Location.decision_has_effect_for(&key));
        assert!(!Resource::Account(AccountResource::Email).decision_has_effect_for(&key));
    }

    /// Contra la ruta de un ejecutable no cambió nada.
    ///
    /// En particular la captura de pantalla sigue sin contar por ahí: nadie la
    /// consulta contra un binario, así que guardarla seguiría siendo un
    /// interruptor muerto. Que ahora cuente por el portal no la habilita acá.
    #[test]
    fn contra_un_binario_sigue_valiendo_lo_de_siempre() {
        let ruta = "/usr/bin/vasak-connect";

        assert!(Resource::Camera.decision_has_effect_for(ruta));
        assert!(Resource::Microphone.decision_has_effect_for(ruta));
        assert!(Resource::Credentials.decision_has_effect_for(ruta));
        assert!(Resource::Account(AccountResource::Email).decision_has_effect_for(ruta));

        assert!(!Resource::ScreenCapture.decision_has_effect_for(ruta));
        assert!(!Resource::Location.decision_has_effect_for(ruta));
    }

    /// Las tres decisiones viajan por el bus como texto y vuelven iguales.
    ///
    /// Se comprueba el texto exacto y no sólo la ida y vuelta: estas cadenas son
    /// el contrato con el agente, y cambiarlas haría que un agente viejo lea
    /// «sin decidir» donde el servicio dijo «denegado» — o sea, que un rechazo
    /// se vuelva a preguntar.
    #[test]
    fn las_decisiones_viajan_como_texto() {
        assert_eq!(Decision::Allowed.as_id(), "allowed");
        assert_eq!(Decision::Denied.as_id(), "denied");
        assert_eq!(Decision::Unknown.as_id(), "unknown");

        for decision in [Decision::Allowed, Decision::Denied, Decision::Unknown] {
            assert_eq!(Decision::from_id(decision.as_id()), Some(decision));
        }
        assert_eq!(Decision::from_id("quizá"), None);
    }

    /// Una identidad del portal no tiene alcance declarado, así que puede pedir.
    ///
    /// `SCOPED_BINARIES` acota aplicaciones propias por su ruta instalada, y una
    /// identidad del portal no es ninguna de ésas. Si esto diera falso, el
    /// servicio negaría sin preguntar todo lo que llega por el portal.
    #[test]
    fn una_identidad_del_portal_puede_pedir() {
        let key = portal_key("com.google.Chrome").expect("identidad válida");
        assert!(may_request(&key, "camera"));
        assert!(may_request(&key, "screen-capture"));
    }
}
