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
pub const DELEGATE_BINARIES: [&str; 1] = ["/usr/bin/vasak-accounts"];

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
/// Las aplicaciones de correo, calendario, contactos y chats todavía no
/// existen. Cada una entra acá el día que se escriba, con su capacidad y
/// ninguna más.
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
    // El bucle que mantiene al día el correo. Corre con la cuenta de la
    // persona, aparte del servicio de cuentas, porque habla IMAP con servidores
    // ajenos y eso no puede pasar por un proceso de root.
    //
    // Sólo el correo: el calendario es de la aplicación de calendario y los
    // contactos de la suya. Que viva en el mismo repositorio que el servicio no
    // le da nada — le pide los tokens por el mismo camino que cualquier otra
    // aplicación, y este límite lo alcanza igual.
    ("/usr/bin/vasak-accounts-sync", &["account.email"]),
    // El calendario. Lee los eventos por CalDAV de las cuentas conectadas.
    //
    // No los contactos, aunque vivan en el mismo servidor y detrás de la misma
    // contraseña: la agenda es de la aplicación de contactos. Un servidor
    // Nextcloud entrega las dos cosas con la misma credencial, así que sin esta
    // línea la separación sería una convención y no un límite.
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
    ("/usr/bin/vasak-mail", &[]),
    // La libreta de direcciones. El otro lado de la línea que separa los
    // contactos de los calendarios.
    //
    // Con esta entrada la lista queda simétrica: `vasak-calendar` puede pedir
    // los eventos y no la agenda, y `vasak-contacts` la agenda y no los
    // eventos. Sin las dos, el límite lo tendría sólo una de ellas — y las dos
    // llegan al mismo servidor con la misma contraseña, así que alcanzaba con
    // reemplazar la que no estaba acotada.
    ("/usr/bin/vasak-contacts", &["account.contacts"]),
];

/// Si `binary_path` puede llegar a pedir `resource_id`.
///
/// Verdadero para todo lo que no esté en la lista: ver arriba por qué.
pub fn may_request(binary_path: &str, resource_id: &str) -> bool {
    match scope_of(binary_path) {
        Some(alcance) => alcance.contains(&resource_id),
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
    if let Some((_, alcance)) = SCOPED_BINARIES
        .iter()
        .find(|(instalado, _)| *instalado == binary_path)
    {
        return Some(alcance);
    }

    #[cfg(debug_assertions)]
    if std::env::var_os("VASAK_PERMISSIONS_TEST_ROOT").is_some() {
        let nombre = std::path::Path::new(binary_path).file_name();
        if let Some((_, alcance)) = SCOPED_BINARIES.iter().find(|(instalado, _)| {
            std::path::Path::new(instalado).file_name() == nombre
        }) {
            return Some(alcance);
        }
    }

    None
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
        matches!(
            self,
            Resource::Account(_)
                | Resource::Camera
                | Resource::Microphone
                | Resource::Credentials
        )
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
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        if let Some(capability) = id.strip_prefix("account.") {
            return AccountResource::from_id(capability).map(Resource::Account);
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

        // A program the user can write must never be able to claim it is
        // asking on another program's behalf — it would name whichever
        // already-approved program it liked.
        assert!(!is_delegate("/home/someone/.local/bin/vasak-accounts"));
        assert!(!is_delegate("/tmp/vasak-accounts"));
        assert!(!is_delegate("vasak-accounts"));
        assert!(!is_delegate("/usr/bin/anything-else"));
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
mod tests_alcance {
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

    /// El bucle de correo llega al correo y a nada más.
    ///
    /// Corre aparte del servicio de cuentas y con la cuenta de la persona, así
    /// que es una aplicación como cualquier otra a los ojos de esta lista — y le
    /// corresponde el mismo trato.
    #[test]
    fn el_bucle_de_correo_solo_llega_al_correo() {
        let sync = "/usr/bin/vasak-accounts-sync";

        assert!(may_request(sync, "account.email"));
        for prohibido in [
            "account.calendar",
            "account.contacts",
            "account.drive",
            "account.chat",
            "credentials",
        ] {
            assert!(!may_request(sync, prohibido), "no tenía que poder pedir '{prohibido}'");
        }
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
            assert!(!may_request(calendario, prohibido), "no tenía que poder pedir '{prohibido}'");
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
            assert!(!may_request(contactos, prohibido), "no tenía que poder pedir '{prohibido}'");
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
        let correo = "/usr/bin/vasak-mail";

        assert_eq!(scope_of(correo), Some(&[][..]));
        for recurso in [
            "account.email",
            "account.contacts",
            "account.calendar",
            "account.drive",
            "credentials",
        ] {
            assert!(!may_request(correo, recurso), "no tenía que poder pedir '{recurso}'");
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
