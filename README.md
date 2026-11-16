# Proyecto Active Directory: Arquitectura Multi-DC, Modelo de Seguridad por Niveles (Tier 0/1/2), Hardening y Validación Forense

## Ficha Técnica del Proyecto y Palabras Clave ATS

*   **Autor / Candidato**: Kanu — Analista de Ciberseguridad
*   **Rol en el Proyecto**: Arquitecto de Sistemas de Identidad, Administrador de Sistemas AD DS y Analista Forense de Ciberseguridad
*   **Entorno Tecnológico**: Windows Server 2022 Standard, Proxmox VE (Hipervisor KVM/QEMU), Active Directory Domain Services (AD DS), PowerShell 5.1 / 7.x, DNS Integrado, DFSR, Auditpol.
*   **Hard Skills e Habilidades Técnicas ATS**: Active Directory, AD DS, Modelo de Seguridad por Niveles (Tiering Model Tier 0/1/2), Group Policy Objects (GPO), Hardening de Infraestructura, Análisis Forense de Eventos de Seguridad, Protocolos Kerberos y NTLM, Roles FSMO, Replicación Multi-DC, Diagnóstico DFSR, Configuración Auditpol, Respuesta ante Incidentes de Seguridad, Troubleshooting de Infraestructura, Scripts en PowerShell, Virtualización Proxmox VE, Optimización ATS, Metodología STAR.

---

## 1. Resumen Ejecutivo y Objetivos Estratégicos

El presente proyecto documenta el diseño, despliegue, hardening y validación forense de un entorno empresarial de Active Directory Domain Services (AD DS) construido desde cero sobre infraestructura virtualizada Proxmox VE. La iniciativa fue concebida para abordar los desafíos contemporáneos de gestión de identidades y contención de movimientos laterales en redes corporativas, estructurando un modelo de administración delegada por niveles (Tiering Model Tier 0 / Tier 1 / Tier 2) compuesto por 18 Unidades Organizativas (OUs), redirección estandarizada de contenedores de sistema y una convención estricta de nombres para cuentas de usuario, grupos y servicios.

Sobre esta arquitectura de identidad se implementaron tres bloques fundamentales de controles de ciberseguridad: un sistema de auditoría avanzada de eventos de inicio de sesión basado en 6 subcategorías críticas, una política de dominio para el bloqueo automático de cuentas ante ataques de fuerza bruta o Password Spraying, y una directiva de aislamiento estricto que restringe el acceso de identidades no privilegiadas (Tier 2) sobre activos críticos de infraestructura (Tier 0). Cada control fue sometido a pruebas de penetración y validación forense, registrando firmas de eventos específicas y demostrando principios fundamentales de seguridad como la precedencia estricta de directivas de denegación (`Deny > Allow`).

Finalmente, la infraestructura fue expandida a una topología de alta disponibilidad mediante la adición de un segundo Controlador de Dominio (`DC02`) con replicación en tiempo real. Se ejecutaron pruebas de resiliencia mediante la simulación de caídas catastróficas del Controlador de Dominio primario (`DC01`, ostentador de los 5 roles FSMO), analizando la tolerancia a fallos en la autenticación Kerberos, la capacidad de procesamiento de cambios de contraseña propios sin la presencia del PDC Emulator, y la resolución de incidentes de replicación post-recuperación mediante el diagnóstico de firmas de error DNS y la normalización de líneas temporales de auditoría.

---

## 2. Arquitectura de Infraestructura e Identidad por Niveles

### 2.1 Infraestructura Física y Entorno de Virtualización

El laboratorio se ejecutó sobre un hipervisor Proxmox VE alojado en hardware dedicado. Durante el despliegue inicial se identificó una restricción de hardware crítica: el procesador del hipervisor no soporta la extensión de instrucciones de cifrado AES-NI. Al intentar iniciar las máquinas virtuales de Windows Server 2022 utilizando el tipo de CPU predeterminado en Proxmox (`x86-64-v2-AES`), la virtualización abortaba inmediatamente con el error `QEMU exit code 1` debido a la falta del flag de instrucción. La incidencia se resolvió configurando explícitamente el tipo de CPU de las máquinas virtuales como `host`, lo que permitió pasar de forma transparente las capacidades nativas del procesador a las máquinas servidoras.

La topología de red se estableció en la subred privada `192.168.1.0/24` a través de un puente virtual compartido (`vmbr0`). El servidor DHCP del enrutador principal fue delimitado al rango `.2`–`.127`, reservando el segmento `.128`–`.254` para la asignación de direcciones IP estáticas a servidores y controladores de dominio.

| Componente | Dirección IP | Sistema Operativo / Especificaciones | Rol y Estado Operativo |
| :--- | :--- | :--- | :--- |
| **Hipervisor Proxmox VE** | 192.168.1.100 | Proxmox VE sobre Intel Xeon X3470 (4c/8t ~2.93 GHz, 32 GB RAM, ZFS Storage) | Hipervisor base. Estado: Estabilizado con CPU type host. |
| **DC01** | 192.168.1.130 | Windows Server 2022 Standard Evaluation (Español, Desktop Experience) | Controlador de Dominio Primario, Catálogo Global (GC), Servidor DNS, 5 Roles FSMO. |
| **DC02** | 192.168.1.132 | Windows Server 2022 Standard (VM 102, 2 GB RAM, Disco 60 GB VirtIO, vTPM) | Controlador de Dominio Adicional, Catálogo Global (GC), Servidor DNS. |
| **WS01** | 192.168.1.131 | Windows Server 2022 Standard (Configurado como Estación de Trabajo) | Cliente de Dominio Tier 2. DNS primario DC01, secundario DC02. |

### 2.2 Diseño de Identidad y Árbol de Unidades Organizativas (Tiering Model)

Para mitigar el riesgo de movimiento lateral derivado del compromiso de credenciales no privilegiadas, se diseñó un modelo de seguridad por niveles basado en la separación de activos e identidades según su alcance de impacto:

*   **Tier 0**: Activos de control total del bosque, incluyendo controladores de dominio (`DC01`, `DC02`), cuentas de administración del dominio y credenciales de infraestructura crítica.
*   **Tier 1**: Servidores de aplicaciones corporativas, bases de datos y cuentas de servicio asociadas a servidores.
*   **Tier 2**: Estaciones de trabajo de usuarios finales (`WS01`), equipos portátiles y cuentas de usuario estándar.

La implementación práctica se materializó mediante un árbol de 18 Unidades Organizativas (OUs) con prefijos estructurales `Tier0-`, `Tier1-` y `Tier2-`. Mediante los comandos de administración `redircmp` y `redirusr`, se modificaron las rutas por defecto del dominio `lab.local`, forzando a que cualquier nuevo equipo o usuario unido al dominio sea redirigido automáticamente a sus OUs correspondientes (`OU=OU-Estaciones-Trabajo` y `OU=OU-Usuarios,OU=OU-Tier2-Usuarios`, respectivamente) en lugar de los contenedores por defecto `CN=Computers` y `CN=Users`.

Se estableció una convención de nomenclatura obligatoria utilizando prefijos en las propiedades `sAMAccountName` y `CN`: `USR-` para usuarios finales, `GRP-` para grupos de seguridad y `SVC-` para cuentas de servicio. Un detalle técnico documentado durante la creación de objetos es que la combinación del prefijo `OU-` en el nombre visual de la OU con la palabra clave `OU=` de LDAP produce Nombres Distinguidos (DN) del tipo `OU=OU-Usuarios,OU=OU-Tier2-Usuarios,DC=lab,DC=local`. La omisión de este doble prefijo al escribir DNs de memoria genera excepciones de objeto no encontrado (`ADIdentityNotFoundException`), por lo que se estableció como norma operativa consultar previamente el DN exacto mediante `Get-ADOrganizationalUnit`.

---

## 3. Implementación de Controles de Seguridad y Hardening

### 3.1 Auditoría Avanzada de Eventos de Seguridad (`GPO-Auditoria-Base`)

En lugar de modificar la Directiva Predeterminada del Dominio (*Default Domain Policy*), la cual se reservó exclusivamente para configuraciones globales de contraseñas y bloqueos, se creó la directiva dedicada `GPO-Auditoria-Base` vinculada a la raíz del dominio. Esta decisión de diseño facilita el control de versiones, simplifica las auditorías de cumplimiento y permite una reversión granular sin alterar las políticas fundamentales del bosque.

Mediante esta directiva se habilitaron 6 subcategorías principales de auditoría detallada en modalidades de Éxito y Error:

1.  **Inicio y Cierre de Sesión (Logon/Logoff)**: Captura de eventos 4624 (inicio de sesión exitoso) y 4625 (inicio de sesión fallido), incluyendo el tipo de inicio de sesión (*Logon Type*) y la dirección IP de origen.
2.  **Bloqueo de Cuentas**: Seguimiento del evento 4740 (cuenta bloqueada por superar el umbral de intentos fallidos).
3.  **Gestión de Cuentas de Usuario**: Monitoreo de eventos 4720 a 4738 (creación, modificación, habilitación y eliminación de usuarios).
4.  **Gestión de Grupos de Seguridad**: Registro de eventos 4728, 4729, 4732 y 4733 (modificación de membresías en grupos globales y locales).
5.  **Creación de Procesos**: Captura del evento 4688 con la inclusión explícita de la línea de comandos ejecutada en el proceso secundario.
6.  **Validación de Credenciales y Kerberos**: Inspección de eventos 4776 (validación NTLM por el controlador de dominio) y 4771 (fallos de preautenticación Kerberos en el KDC).

### 3.2 Directiva de Bloqueo de Cuentas y Contraseñas de Dominio

A través de la *Default Domain Policy* (DDP) se establecieron las reglas paramétricas para salvaguardar la autenticación contra ataques automatizados:

*   **Longitud Mínima de Contraseña**: 7 caracteres.
*   **Complejidad de Contraseña**: Habilitada (`ComplexityEnabled = True`), requiriendo tres de cuatro categorías de caracteres.
*   **Edad Mínima de Contraseña**: 1 día (`MinPasswordAge = 1.00:00:00`). Evita que un usuario cambie repetidamente su contraseña en segundos para eludir el historial.
*   **Historial de Contraseñas**: 24 contraseñas recordadas (`PasswordHistoryCount = 24`).
*   **Umbral de Bloqueo de Cuenta**: 5 intentos fallidos consecutivos.
*   **Duración del Bloqueo**: 15 minutos.
*   **Ventana de Observación del Bloqueo**: 15 minutos.

La cuenta del Administrador integrado (RID 500) quedó exenta del bloqueo automático por diseño de laboratorio para prevenir escenarios de Denegación de Servicio (DoS) sobre la administración principal, documentando que en entornos de producción dicha exención exige controles de monitoreo reinforced sobre el ID 500.

### 3.3 Aislamiento de Identidades Tier 2 sobre Activos Tier 0 (`GPO-Aislamiento-Tier2-En-Tier0`)

Para garantizar la regla operativa fundamental del modelo por niveles ("una credencial de nivel inferior jamás debe poder autenticarse contra un activo de nivel superior"), se configuró la directiva `GPO-Aislamiento-Tier2-En-Tier0` y se vinculó **únicamente** a la Unidad Organizativa `Domain Controllers`.

La directiva aplica restricciones de Asignación de Derechos de Usuario (*User Rights Assignment*) configurando los derechos de denegación explícita `Deny log on locally` (Denegar el inicio de sesión local) y `Deny log on through Remote Desktop Services` (Denegar el inicio de sesión a través de Escritorio Remoto) sobre el grupo de seguridad `GRP-Tier2-NoLogon`, el cual agrupa a todas las identidades de usuario estándar del dominio (`USR-jperez`, `USR-mlopez`).

Durante la fase de diseño se identificó un error crítico de vinculación dual donde la directiva había sido vinculada accidentalmente a la raíz del dominio, provocando que los usuarios Tier 2 no pudieran iniciar sesión ni siquiera en sus propias estaciones de trabajo (`WS01`). El diagnóstico realizado mediante el cmdlet `Get-GPInheritance` permitió identificar la herencia no intencionada y corregir la vinculación hacia la OU de controladores de dominio exclusivamente.

Como medida complementaria de hardening, el acceso por Escritorio Remoto (RDP) a los controladores de dominio fue deshabilitado mediante la directiva `GPO-RDP-DC-Deshabilitado`, la cual escribe la clave de registro `fDenyTSConnections = 1` en la ruta de directivas de grupo `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`. La verificación mediante el cmdlet `Test-NetConnection -Port 3389` confirmó que el puerto de escucha quedó cerrado.

---

## 4. Logros Técnicos y Evidencia Forense (Metodología STAR)

En esta sección se presentan los logros más destacados del proyecto, estructurados bajo el formato internacional STAR (Situación, Tarea, Acción, Resultado) recomendado para la optimización de perfil profesional en filtros ATS.

### 4.1 Validación Forense del Aislamiento de Accesos (Firma 0xc000015b)

*   **Situación**: Se requería verificar experimentalmente que el modelo de aislamiento impidiera eficazmente a los usuarios de nivel Tier 2 interactuar con la consola interactiva o la interfaz RDP de los controladores de dominio (`DC01` y `DC02`).
*   **Tarea**: Ejecutar intentos de inicio de sesión legítimos en consola local y Escritorio Remoto utilizando credenciales válidas de usuarios Tier 2 (`USR-jperez` y `USR-mlopez`), analizando la respuesta del sistema y la generación de eventos en el registro de seguridad.
*   **Acción**: Se lanzaron intentos de acceso desde la consola de Proxmox VE y desde la estación `WS01` vía `mstsc.exe`. Posteriormente se inspeccionaron los registros de eventos de seguridad de Windows mediante scripts de PowerShell filtrando el evento ID 4625.
*   **Resultado**: Todos los intentos de acceso fueron rechazados con éxito. La inspección del registro de seguridad reveló la firma forense de autorización `Status: 0xc000015b` (`LOGON_TYPE_NOT_GRANTED`) y motivo de fallo `%%2308`, confirmando que el rechazo ocurrió en la capa de derechos de usuario y no por un fallo de credenciales (las cuales eran correctas).

| Canal de Intento | Cuenta Evaluada | Tipo de Logon (Logon Type) | Código de Estatus Forense | Sub-Estatus | Origen del Intento | Resultado del Control |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Consola Local DC01** | LAB\mlopez | 2 (Interactive) | 0xc000015b | 0x0 | 127.0.0.1 | Rechazado por Directiva |
| **Consola Local DC01** | LAB\jperez | 2 (Interactive) | 0xc000015b | 0x0 | 127.0.0.1 | Rechazado por Directiva |
| **Escritorio Remoto (RDP)** | LAB\jperez | 10 (RemoteInteractive) | 0xc000015b | 0x0 | 192.168.1.131 (WS01) | Rechazado por Directiva |

### 4.2 Demostración Experimental de la Precedencia Deny > Allow

*   **Situación**: Existía la hipótesis de que el rechazo del acceso por Escritorio Remoto podía atribuirse simplemente a la ausencia de permisos de concesión (*Allow*) en lugar de la ejecución activa de la directiva de denegación (*Deny*).
*   **Tarea**: Diseñar un experimento de atribución para aislar la variable de permisos, concediendo permisos explícitos de acceso RDP a un usuario Tier 2 y evaluando cuál directiva prevalecía.
*   **Acción**: Se otorgó membresía explícita a la cuenta `USR-jperez` dentro del grupo local predeterminado de usuarios de escritorio remoto. Para evitar problemas de localización en el sistema operativo en español ("Usuarios de escritorio remoto"), la membresía se asignó haciendo referencia a su Identificador de Seguridad bien conocido (Well-Known SID `S-1-5-32-555`). Con el permiso *Allow* confirmado, se repitió el intento de conexión RDP desde `WS01`.
*   **Resultado**: El intento de acceso continuó siendo bloqueado de forma categórica. El registro de seguridad registró nuevamente el evento 4625 con la firma `0xc000015b`, demostrando empíricamente la regla de arquitectura de seguridad Windows donde las directivas de denegación explícita (*Deny*) superan a cualquier concesión de permisos (*Allow*). La correlación multi-canal confirmó el bloqueo de forma simultánea en la aplicación cliente (`mstsc` error 0x3/0x9), la capa de transporte (`RdpCoreTS` evento 226/motivo 4407) y la auditoría de seguridad.

### 4.3 Expansión Multi-DC y Latencia de Replicación de Directorio

*   **Situación**: El dominio `lab.local` operaba sobre un único controlador de dominio (`DC01`), representando un punto único de fallo (SPOF) para la autenticación del negocio.
*   **Tarea**: Promover un segundo servidor (`DC02`) como Controlador de Dominio Adicional, Catálogo Global y servidor DNS, logrando una sincronización completa y transparente de las 5 particiones de Active Directory.
*   **Acción**: Se ejecutó el asistente de promoción sobre Windows Server 2022, integrando `DC02` en el sitio `Default-First-Site-Name`. Tras la promoción, se verificó la salud de la topología mediante herramientas administrativas (`repadmin /replsummary`, `repadmin /showrepl`) y se desarrolló un script de PowerShell para medir la latencia de replicación mediante técnicas de sondeo (*polling*) en intervalos de 5 segundos.
*   **Resultado**: Se alcanzó un estado final de 0 errores en las 5 particiones del directorio en ambas direcciones de replicación (`DC01` $\leftrightarrow$ `DC02`). La latencia de replicación intra-sitio para la creación y posterior eliminación del objeto de prueba `USR-testrepl` fue medida en $\le 5$ segundos, registrando valores de timestamp `whenCreated` idénticos en ambos controladores.

---

## 5. Resiliencia Multi-DC, Pruebas de Failover y Análisis Incidental

### 5.1 Diagnóstico de la Arquitectura del Contador `badPwdCount`

Durante las pruebas en la topología multi-DC se diseñó un experimento para analizar cómo se distribuyen los contadores de intentos fallidos de contraseña (`badPwdCount`) entre los controladores de dominio. Se introdujeron 4 intentos fallidos deliberados mediante el comando `net use \\DC02\IPC$ ClaveErronea /user:LAB\jperez` ejecutado desde `DC01`.

Los resultados obtenidos arrojaron tres descubrimientos fundamentales sobre el comportamiento interno de Active Directory:

1.  **El atributo `badPwdCount` no se replica**: El contador se incrementa exclusivamente en el Controlador de Dominio que procesa y valida la solicitud de autenticación. Tras los 4 intentos, la consulta mediante `Get-ADUser` reflejó un valor de `badPwdCount = 4` en `DC01` y un valor de `0` (atributo ausente) en `DC02`.
2.  **Independencia del Destino UNC bajo Kerberos**: El intento de conexión dirigido hacia `\\DC02\IPC$` no cargó el contador de `DC02`. Esto se debe a que la autenticación mediante el protocolo Kerberos envía la solicitud de servicio (*AS-REQ*) al Centro de Distribución de Claves (KDC) seleccionado por el servicio *DC Locator* del cliente (en este caso `DC01`), independientemente de cuál sea el servidor destino del recurso compartido.
3.  **Función Agregadora del PDC Emulator**: El rol FSMO de PDC Emulator es el único encargado de centralizar y sumar los contadores `badPwdCount` de todos los controladores de dominio del bosque para la toma de decisiones sobre el bloqueo de cuentas.

Durante esta verificación se identificó un hallazgo colateral crítico para el análisis forense: los registros de `DC02` presentaban un desfase de 6 horas respecto a `DC01`. Tras descartar un problema de desincronización de reloj (*Clock Drift*, el cual habría roto el protocolo Kerberos al superar la tolerancia máxima de 5 minutos), se diagnosticó que la causa era una configuración incorrecta de la zona horaria en el sistema operativo. El problema fue corregido mediante `Set-TimeZone`, concluyendo que la normalización de zonas horarias entre servidores es un requisito indispensable para la reconstrucción precisa de líneas temporales durante la investigación de incidentes.

### 5.2 Pruebas de Failover FSMO y Falsación de Hipótesis sobre el PDC Emulator

Se evaluó la resiliencia del dominio ante la caída total del Controlador de Dominio primario (`DC01`), portador de los 5 roles FSMO (Schema Master, Domain Naming Master, PDC Emulator, RID Master y Infrastructure Master). Se ejecutaron dos protocolos de apagado: un corte abrupto de energía virtual (STOP en Proxmox VE) y un apagado controlado por software.

Durante la caída de `DC01`, se observaron los siguientes comportamientos desde la estación de trabajo `WS01`:

*   **Redirección de Autenticación**: El servicio *DC Locator* detectó la inalcanzabilidad de `DC01` y reorientó automáticamente las solicitudes de inicio de sesión y validación de credenciales Kerberos hacia `DC02`.
*   **Acceso a Recursos**: El montaje de recursos compartidos de red continuó operando sin interrupción.
*   **Restablecimiento Administrativo de Contraseñas**: El restablecimiento ejecutado por un administrador fue procesado con éxito por `DC02`, confirmando que cualquier DC escribible puede procesar escrituras LDAP en el directorio.
*   **Falsación de Hipótesis en el Cambio de Contraseña Propio**: La predicción inicial del laboratorio sugería que un usuario final no podría cambiar su propia contraseña a través de la combinación de teclas `Ctrl+Alt+Supr` con el PDC Emulator fuera de servicio. Sin embargo, el experimento **falsificó empíricamente la hipótesis**: el usuario `USR-jperez` cambió su contraseña exitosamente desde `WS01`, siendo la solicitud procesada y aceptada por `DC02`. Este hallazgo demostró que el cambio de contraseña propio es una operación de escritura SAMR que cualquier controlador de dominio escribible puede procesar, y que la preferencia por el PDC Emulator es una optimización de consistencia de datos y no una dependencia dura del sistema.

Inmediatamente después del cambio exitoso, se intentó realizar un segundo cambio de contraseña, el cual fue rechazado por el dominio con el mensaje: *"El valor proporcionado para la nueva contraseña no cumple los requisitos de longitud, complejidad o historial del dominio"*. La inspección detallada reveló que la contraseña propuesta cumplía ampliamente con la longitud y complejidad; el rechazo fue provocado por la directiva de **Edad Mínima de la Contraseña** (`MinPasswordAge = 1 día`). Este evento proporcionó dos lecciones clave: validó empíricamente el funcionamiento de la política DDP y demostró que los mensajes de error de Windows agrupan múltiples causas bajo un texto genérico, exigiendo al analista diagnosticar mediante consultas a los atributos del directorio (`PasswordLastSet`) en lugar de guiarse por el texto del sistema.

### 5.3 Post-Mortem del Error de Replicación 8524 y Carrera de Arranque DNS

Tras el reinicio de los controladores de dominio posterior a las pruebas de failover, las herramientas de diagnóstico reportaron la degradación de la replicación con el código de error `8524`: *"El nombre DNS basado en el GUID DSA no está registrado en ningún servidor DNS"*, acompañado de eventos `0x3F6` en el registro del sistema.

```
Firma del Diagnóstico dcdiag /v:
"El nombre DNS basado en el GUID DSA 31d792da-eebf-453b-ab77-0ffb14d28f74._msdcs.lab.local
no está registrado en ningún servidor DNS"
```

El análisis detallado permitió determinar que el error `8524` post-arranque no era consecuencia de un daño en la base de datos por el apagado de la máquina, sino el resultado de una **carrera de arranque** (*startup race condition*) entre el servicio de replicación de Active Directory y el servicio servidor DNS. Al iniciar el sistema operativo, el servicio de replicación intenta resolver la dirección de su par a través de su CNAME basado en el GUID DSA antes de que el servicio DNS local haya completado su inicialización. Al no disponer de un resolutor activo en esa ventana de segundos, la consulta falla y la replicación entra en estado de degradación.

La resolución definitiva del incidente se logró mediante el comando de replicación manual en PowerShell:

```powershell
repadmin /syncall /AdeP
```

Durante la aplicación de la solución se descubrió una propiedad operativa crítica: el comando `repadmin /syncall` es **direccional**, es decir, ejecuta un empuje de datos (*push*) exclusivamente desde el controlador de dominio donde es invocado. Ejecutar el comando únicamente en `DC01` sanó la dirección `DC01` $\rightarrow$ `DC02`, dejando la dirección opuesta en estado de error. Para restaurar completamente la topología fue necesario ejecutar el comando de forma independiente en ambos controladores de dominio, logrando una convergencia perfecta a 0 errores en las 5 particiones con deltas de replicación de 48 segundos y 5 minutos 21 segundos.

Como medida de mitigación permanente contra la carrera de arranque, se estableció la buena práctica de configurar la interfaz de red de cada controlador de dominio con su propia dirección IP en el DNS primario (127.0.0.1 o IP local) y la IP del controlador par en el DNS secundario, garantizando la resolución local durante el proceso de inicio.

---

## 6. Lecciones Aprendidas, Troubleshooting y Análisis de Causa Raíz

A continuación se resumen las principales lecciones técnicas derivadas del troubleshooting del proyecto, categorizadas por su dominio tecnológico:

### 6.1 Administración de Registro y PowerShell

*   **Terminología de Claves de Registro**: La directiva de grupo (GPO) escribe configuraciones de Escritorio Remoto en la ruta en plural `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, mientras que la configuración local del sistema reside en la clave en singular `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`. Utilizar la ruta incorrecta en scripts provoca respuestas falsas de clave no encontrada (`Test-Path = False`).
*   **Comportamiento de `Set-ItemProperty`**: Introducir un error tipográfico en el parámetro `-Name` del cmdlet `Set-ItemProperty` no genera una excepción de error; en su lugar, crea silenciosamente una propiedad nueva en el registro, dejando la propiedad legítima intacta. Se establece la norma de verificar siempre la modificación mediante `Get-ItemProperty`.
*   **Filtrado Eficiente de Eventos**: En el uso de `Get-WinEvent` con el parámetro `-FilterHashtable`, la inclusión de múltiples IDs de evento debe realizarse dentro de un arreglo en una sola clave (`Id = 4625,4771,4776`). La duplicación de claves `Id =` dentro de la hashtable genera errores de sintaxis en el intérprete de PowerShell.

### 6.2 Metodología Forense y Diagnóstico de Incidentes

*   **Delimitación de Ventanas Temporales**: La consulta de registros de eventos mediante scripts exige utilizar fechas literales validadas previamente contra la hora del sistema `(Get-Date)`. Establecer ventanas de tiempo con fechas futuras produce falsos negativos ("0 eventos encontrados"), constituyendo uno de los errores diagnósticos más comunes en análisis forense.
*   **Atribución de Eventos por Protocolo**: Los intentos fallidos de inicio de sesión sobre recursos de red autenticados mediante Kerberos generan eventos `4771` (fallo de preautenticación con error `0x18`) en el controlador de dominio KDC, y no eventos `4625` en el servidor final del recurso compartido. Por el contrario, las autenticaciones NTLM generan eventos `4625` e `4776`.

---

## 7. Comandos de Referencia y Verificación en PowerShell

Esta sección proporciona la biblioteca de comandos en PowerShell utilizada para auditar, diagnosticar y verificar el estado de salud de la infraestructura desplegada.

### 7.1 Salud de Replicación y Topología de Dominio

```powershell
# Comprobación general del estado de replicación de Active Directory
repadmin /replsummary
repadmin /showrepl
repadmin /kcc

# Sincronización manual direccional (Ejecutar en cada Controlador de Dominio)
repadmin /syncall /AdeP

# Consulta de Dominio, Catálogos Globales y Roles FSMO
Get-ADDomainController -Filter * | Select-Object Name, Site, IsGlobalCatalog, IPv4Address
netdom query fsmo
nltest /dsgetdc:lab.local

# Verificación de registros SRV de DNS y CNAME de GUID DSA
Resolve-DnsName _ldap._tcp.dc._msdcs.lab.local -Type SRV
Resolve-DnsName 34f64fe9-d87f-4a7b-84c6-a7936c01c220._msdcs.lab.local -Server 127.0.0.1
Resolve-DnsName 31d792da-eebf-453b-ab77-0ffb14d28f74._msdcs.lab.local -Server 127.0.0.1
```

### 7.2 Auditoría de Seguridad y Eventos de Autenticación

```powershell
# Extracción de eventos de inicio de sesión fallido (NTLM y Kerberos) con delimitación temporal
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625, 4771, 4776
    StartTime = [datetime]'2026-11-10 00:00:00'
    EndTime   = (Get-Date)
} | Select-Object TimeCreated, Id, @{N='Cuenta'; E={$_.Properties[0].Value}} | Sort-Object TimeCreated | Format-Table -AutoSize

# Lectura directa del contador badPwdCount por Controlador de Dominio
Get-ADUser jperez -Server DC01.lab.local -Properties badPwdCount, LockedOut | Select-Object Name, badPwdCount, LockedOut
Get-ADUser jperez -Server DC02.lab.local -Properties badPwdCount, LockedOut | Select-Object Name, badPwdCount, LockedOut

# Inspección de la Política Predeterminada de Contraseñas del Dominio
Get-ADDefaultDomainPasswordPolicy | Format-List ComplexityEnabled, MinPasswordLength, MinPasswordAge, PasswordHistoryCount, LockoutThreshold
Get-ADUser jperez -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
```

### 7.3 Verificación de Hardening y Red

```powershell
# Comprobación de estado del puerto RDP (3389) en el servidor local
Test-NetConnection localhost -Port 3389

# Consulta de la directiva de deshabilitación de RDP en el Registro de Windows
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDenyTSConnections

# Verificación de sincronización de huso horario y fuente de tiempo NTP
hostname
[DateTime]::UtcNow
Get-TimeZone
w32tm /query /source
```
