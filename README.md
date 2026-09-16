# vasak-permissions

El servicio de permisos de VasakOS. Responde una sola pregunta —«¿puede este
programa usar esto?»— para la cámara, el micrófono, la captura de pantalla y las
cuentas en línea, y recuerda lo que la persona contestó.

## Por qué es un servicio de sistema

Las dos cosas que hacen falta para que un permiso signifique algo son
imposibles dentro de la sesión del usuario:

- **Saber quién llama** exige leer `/proc/<pid>/exe` de un proceso ajeno, que un
  proceso sin privilegios no puede hacer.
- **Guardar la respuesta** exige un archivo que los programas del usuario no
  puedan reescribir. Si vive en su directorio de configuración, cualquier
  programa se otorga lo que quiera y la lista es decorativa.

Por eso corre como root en el bus del sistema, y la política vive en
`/var/lib/vasak-permissions/<uid>.json` con modo 0600.

## Las tres piezas

| Directorio | Qué es |
|---|---|
| `protocol/` | El contrato D-Bus, compartido, para que las dos puntas no se desincronicen |
| `daemon/` | El servicio de sistema (`/usr/bin/vasak-permissions`) |
| `src-tauri/`, `src/` | El agente de diálogo (`/usr/bin/vasak-permissions-agent`) |

El agente no crea ninguna ventana hasta que llega una consulta: un proceso Tauri
con la ventana oculta cuesta unos 150 MB permanentes, y un permiso se pregunta
un puñado de veces en la vida del sistema.

## Cómo no se puede engañar

- El demonio **solo acepta como agente** a un proceso cuyo ejecutable sea
  exactamente `/usr/bin/vasak-permissions-agent`. Escribir en `/usr/bin` requiere
  root, así que ningún programa del usuario puede hacerse pasar por el agente y
  aprobarse todo solo.
- Cambiar un permiso pasa por polkit (`ar.net.vasak.os.permissions.manage`). Sin
  eso, un programa al que se le negó el micrófono llamaría a `SetPermission` y se
  lo otorgaría.
- El PID del llamante se fija con `pidfd` **antes** de leer nada sobre él, para
  que el ejecutable resuelto no pueda ser el de otro proceso que reutilizó el
  número.
- Cada aplicación del sistema tiene **declarado hasta dónde puede pedir**
  (`SCOPED_BINARIES`), y lo que queda afuera se niega **sin preguntar**. Que el
  gestor de archivos pida el correo no es una decisión que alguien tenga que
  tomar: es un fallo o un ataque, y mostrar un diálogo pondría a la persona a
  autorizar justamente lo que la lista existe para impedir. Ver abajo.

## El alcance de cada aplicación

El reparto de capacidades entre aplicaciones —el gestor de archivos a los discos
en la nube, el calendario al calendario— era una convención y nada más. Sin nada
que lo sostenga, bastaba reemplazar el binario del gestor de archivos para pedir
`account.email` con un diálogo que se ve igual que cualquier otro, y la persona
diría que sí porque confía en el gestor de archivos.

`SCOPED_BINARIES`, en el crate del protocolo y al lado de `DELEGATE_BINARIES`,
declara el alcance de cada aplicación propia. Está compilada y no en un archivo
por lo mismo que la otra: es un límite de seguridad, no un catálogo — un archivo
en `/etc` lo cambia root, que es quien instala las aplicaciones de todas formas,
así que no gana nada y sí agrega un lugar más que auditar.

Se hace cumplir en tres puntos, y los tres hacen falta:

| Dónde | Qué impide |
|---|---|
| `decide()` | Que el programa lo pida. Se niega antes de mirar lo guardado y antes de preguntar. |
| `SetPermission` | Que la pantalla lo conceda. Si no, quedaría un interruptor encendido que `decide()` niega igual. |
| `ListPermissions` | Que la pantalla lo muestre. Un interruptor que no hace nada en ninguna de sus dos posiciones es peor que ninguno. |

**Acota, no habilita.** Un programa que no figura en la lista sigue como
siempre: pide, y la persona decide — no se puede enumerar todo lo que alguien
instala, y negar lo no enumerado dejaría al sistema sin poder correr nada de
terceros. Y estar en la lista con un recurso tampoco lo concede: lo sigue
decidiendo la persona.

**Un alcance puede ser vacío**, y el de la pantalla de configuración lo es. Esa
pantalla administra las cuentas —las agrega, las quita, muestra qué aplicaciones
tienen acceso— y no las usa, así que no puede pedir ningún recurso: una
configuración reemplazada no llega a ningún token y ni siquiera puede preguntar.

Lo que el alcance vacío **no** limita, porque de otra forma asustaría: pedir un
recurso es una cosa y administrar la política es otra. `ListPermissions` y
`SetPermission` consultan el alcance del programa **administrado**, no el de
quien administra, así que la configuración sigue pudiendo conceder y quitar
permisos de otros programas. Lo único que no puede es concederse algo a sí misma.

El bucle que mantiene al día el correo —`vasak-accounts-sync`— también está en
la lista, con `account.email` y nada más. Corre con la cuenta de la persona y
aparte del servicio de cuentas, así que a los ojos de esta lista es una
aplicación como cualquier otra y le corresponde el mismo trato: que viva en el
mismo repositorio que el servicio no le da nada.

Las aplicaciones de correo, calendario, contactos y chats todavía no existen.
Cada una entra en la lista el día que se escriba, con su capacidad y ninguna
más.

## El camino del portal

Cámara y captura de pantalla llegan además por `xdg-desktop-portal`, que le
pide el diálogo a un backend. Ese backend es el agente de este repositorio, y
desde ahí **consulta lo guardado antes de preguntar**: lo que ya se concedió no
se vuelve a preguntar, lo que se rechazó se rechaza sin diálogo, y las dos cosas
se pueden retirar desde Configuración.

Antes se preguntaba y se descartaba la respuesta. Medido con Chrome pidiendo
compartir la pantalla: cuatro diálogos idénticos en veinte segundos, y nada
anotado en ninguna parte.

### Contra qué se guarda, y cuánto vale

Contra el `app_id` que entrega el portal, que **no** es la ruta del ejecutable
con la que se identifica todo lo demás. La declara la propia aplicación llamando
a `Register` en `org.freedesktop.host.portal.Registry`, y nadie comprueba que le
corresponda: un programa puede registrarse como `com.google.Chrome` y heredar lo
que Chrome tenga concedido.

Se usa igual porque la alternativa era peor. Un diálogo que reaparece cada vez
no deja a nadie más seguro: enseña a conceder sin leer. Lo que sí se hace es no
disimularlo — estas entradas quedan como no verificadas, viven en un espacio de
nombres aparte (`portal:<app_id>`) y se distinguen a simple vista en el archivo
de política.

Un `app_id` vacío —lo que llega de todo programa que no se registró— se sigue
preguntando cada vez y no se guarda.

## Lo que este servicio todavía no puede hacer cumplir

El camino de arriba cubre lo que **pasa por el portal**, que es por donde piden
la cámara los navegadores y las aplicaciones de videollamada. Lo que no cubre es
la otra puerta: una aplicación que abre `/dev/video0` directamente o que le
habla al socket de PipeWire no pasa por acá y no se entera de ninguna decisión.

Para eso hay un perfil de AppArmor, y sólo alcanza a los AppImage: todo lo que
instaló el gestor de paquetes no tiene perfil. Cerrar la vía de PipeWire está
pendiente de que WirePlumber aplique permisos por cliente — el registro de ese
camino, con lo medido y lo descartado, está en
`vasak-desktop-settings/docs/permisos-de-medios.md`.
