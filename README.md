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

## Lo que este servicio todavía no puede hacer cumplir

Cámara, micrófono y pantalla los entrega PipeWire y el portal de escritorio.
Este servicio puede ser la política a la que ellos consultan, pero la regla se
aplica ahí. Hasta que esa integración exista, el interruptor guarda la decisión
pero no bloquea el acceso.
