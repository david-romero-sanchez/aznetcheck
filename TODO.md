# AzNetCheck TODO

Este documento recoge trabajo pendiente respecto al alcance del producto. No incluye funcionalidades ya presentes en el código. Las tareas de la sección **MVP** son las prioritarias; las posteriores corresponden a capacidades aplazadas explícitamente o extensiones futuras.

## MVP: completar diagnóstico local

- [x] **DNS:** devolver y distinguir de forma consistente `NXDOMAIN`, timeout, respuesta vacía, error del servidor y error de transporte para consultas A y AAAA.
- [x] **DNS:** informar cuando se alcance el límite de profundidad CNAME; conservar la cadena recibida y no tratar una cadena truncada como completa.
- [x] **DNS:** añadir pruebas deterministas de A, AAAA, cadena CNAME, loop, límite de profundidad y errores DNS mediante una abstracción sustituible del resolver.
- [ ] **Target:** añadir pruebas para URLs HTTP, URL con puerto explícito, IPv6 entre corchetes, puertos inválidos, hostnames IDN e inputs malformados.
- [x] **Target/report:** mantener una representación del target coherente y segura en JSON, conservando scheme y puerto útiles sin serializar rutas o query strings que puedan incluir credenciales.
- [x] **Transporte:** seleccionar el transporte comprobado de forma explícita y coherente con `--service`, `--port` y el protocolo del perfil.
- [x] **SQL:** respetar siempre el protocolo TCP para Azure SQL; verificar por tests que el modo HTTPS genérico nunca se ejecute sobre el transporte TDS.
- [x] **Service Bus/Event Hubs:** preservar el resultado `Ambiguous` por sufijo compartido y asegurar que el override explícito selecciona el perfil indicado.
- [ ] **Service detection:** revisar y probar los patrones de servicios y Private Link contra documentación oficial vigente; añadir pruebas para cada entrada del catálogo.
- [ ] **Catálogo:** validar al cargar el JSON IDs duplicados, patrones vacíos, puertos fuera de rango y transportes mal formados; mostrar errores accionables.
- [ ] **Catálogo:** documentar y probar el significado de `portEnd`; actualmente el modelo permite el campo, pero no existe una prueba de conectividad de rangos.
- [ ] **TCP:** añadir pruebas estructuradas de timeout, connection refused, host/network unreachable, cancelación y targets IPv4/IPv6, sin depender de Internet.
- [ ] **TCP:** mostrar de forma clara cada dirección intentada en la salida humana normal o verbose y conservar los resultados parciales por dirección.
- [ ] **TLS/certificado:** exponer handshake y validación de certificado como etapas independientes también cuando TLS falla; distinguir mismatch de hostname, certificado expirado/no vigente y error de cadena con evidencia comprobable.
- [ ] **TLS/certificado:** añadir pruebas de certificados válidos, expirados, no vigentes, hostname mismatch, cadena no confiable y certificado ausente usando fixtures locales.
- [x] **TLS:** decidir cómo asociar la prueba TLS con las direcciones TCP exitosas; evitar que una segunda resolución de hostname oculte diferencias entre IPs.
- [ ] **HTTP:** cubrir con pruebas los status 200, redirects, 401, 403, 404, 405, error de transporte, timeout y cancelación.
- [ ] **HTTP:** seleccionar `HEAD` o `GET` según el perfil y asegurar que el probe siga siendo no destructivo; actualmente los perfiles declaran método, pero el cliente usa GET.
- [ ] **HTTP:** probar que redirects y headers incluidos en la salida estén limitados a valores seguros y que nunca aparezcan Authorization, cookies, tokens, secretos o query strings.
- [ ] **Rule engine:** consolidar reglas fuera del método orquestador para DNS, refusals, timeouts, errores TLS, 401/403 y Private Link; preservar evidencia, interpretación y sugerencias como datos separados.
- [ ] **Summary:** añadir tests para agregación global y conectividad ante todas las combinaciones relevantes, incluidos DNS fail, TCP fail/refused, TLS fail, HTTP 401/403/404 y éxito TCP parcial.
- [ ] **Exit codes:** centralizar el mapeo de resultados y añadir tests para códigos 0 a 4, incluyendo warnings, input inválido, cancelación e inconcluso.
- [ ] **JSON:** añadir pruebas de contrato/versionado para el reporte completo y verificar que la CLI en `--json` escribe exclusivamente JSON en stdout, también ante errores controlados.
- [ ] **CLI:** añadir tests automatizados de argumentos, valores faltantes, opciones no válidas, puertos, timeout y salida/exit codes.
- [x] **CLI:** implementar o retirar opciones aceptadas que actualmente no cambian el comportamiento. En particular, documentar claramente `--no-color` mientras la salida siga siendo texto plano.
- [ ] **CLI:** hacer que `--debug` muestre diagnóstico interno útil sin imprimir secretos; ahora el detalle es limitado y no hay logging estructurado.
- [ ] **CLI:** asegurar que los comandos `dns`, `tcp`, `tls`, `http` y `detect` usen los mismos defaults, overrides y semántica que `check` donde corresponda.
- [ ] **Errores/cancelación:** comprobar Ctrl+C en cada operación DNS/TCP/TLS/HTTP, sin stack trace ni excepción sin tratar.
- [ ] **Timeouts:** aplicar de forma coherente límites por etapa y un límite global de diagnóstico; verificar que la cancelación del usuario no se transforme en un timeout normal.
- [ ] **Privacidad:** ampliar tests de redacción para target original, redirect, errores, resultados y logging; no confiar solo en que la CLI evite mostrar datos.
- [ ] **HTTP/proxy:** documentar claramente en el reporte cuándo HTTP usa proxy del sistema y cuándo TCP/TLS son conexiones directas.
- [x] **Docs:** completar el README con comandos/opciones, la semántica de cada exit code y ejemplos de HTTP 401/403, Private Link, TCP refused y unknown service.
- [ ] **Docs:** corregir afirmaciones que describan capacidades futuras como disponibles; mantener limitaciones sincronizadas con la implementación real.
- [ ] **Cross-platform:** ejecutar build y tests en Windows y Linux en CI, corregir cualquier dependencia accidental de Windows y comprobar macOS antes de anunciar soporte.

## MVP ampliado solicitado

- [ ] Añadir detección y selección de proxy: variables `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` y proxy configurado por .NET.
- [ ] Diseñar `IProxyDiagnostic` y presentar por separado conexión TCP directa y HTTP a través del proxy configurado.
- [x] Añadir opciones funcionales `--ipv4` y `--ipv6`, incluyendo filtrado determinista de direcciones y pruebas.
- [ ] Añadir visualización de consola con Spectre.Console y respetar `--no-color` sin depender únicamente del color para expresar estados.
- [ ] Añadir parsing formal con System.CommandLine y validar help, argumentos, opciones y mensajes de uso mediante tests.
- [ ] Añadir composición de dependencias explícita y centralizada; si se adopta Microsoft.Extensions.DependencyInjection, mantener CLI como único composition root.
- [ ] Añadir logging con Microsoft.Extensions.Logging, enviando logs a stderr y manteniendo stdout limpio para JSON.
- [x] Añadir soporte real para `--verbose` (versión TLS, suite, subject/issuer/SAN/vigencia, CNAME, direcciones y errores de socket seguros).
- [ ] Implementar probes especializados mínimos para Key Vault y Storage o documentar formalmente el alcance genérico si se aplazan.
- [ ] Mostrar transportes disponibles por servicio y permitir seleccionar un transporte opcional; probar Azure Files SMB y AMQP cuando se soliciten.
- [ ] Añadir configuración de familias IP, transportes y probes al plan de diagnóstico con dependencias explícitas y estados `Skipped`/`NotApplicable`.
- [ ] Completar recomendaciones para Private Link con routing, VPN/ExpressRoute, NSG, Azure Firewall, firewall local, DNS forwarding y estado del Private Endpoint, siempre como posibles comprobaciones.
- [ ] Añadir tests de integration etiquetados y opt-in para DNS/TCP/TLS/HTTP; mantenerlos fuera de la validación unitaria por defecto.

## Autenticación Azure, opcional

- [ ] Añadir autenticación Azure.Identity solo cuando el usuario active `--auth`; la ejecución por defecto no debe iniciar login.
- [ ] Añadir `--interactive-auth` como opt-in separado y configurar `DefaultAzureCredential` para no abrir login interactivo inesperadamente.
- [ ] Implementar obtención de token para el scope del servicio detectado, medir duración y registrar origen de credencial cuando Azure.Identity lo permita.
- [ ] Añadir una prueba autenticada no destructiva por servicio y separar adquisición de token de autorización del servicio.
- [ ] Informar tenant solo cuando sea seguro y relevante; no serializar ni loggear tokens, secretos, claves ni contenido de credenciales.
- [ ] Añadir tests con credenciales simuladas para éxito, fallo, cancelación, scope equivocado y ausencia de credenciales.

## Catálogo personalizado y extensibilidad

- [ ] Implementar `--catalog <custom.json>` con schema versionado, validación estricta y errores claros.
- [ ] Definir schema para TLS requerido, HTTP probe, Private DNS zones, aliases, documentación, reglas, port ranges y required/optional tests.
- [ ] Añadir pruebas de compatibilidad del catálogo y mantener el catálogo embebido como default.
- [ ] Diseñar `IServiceDiagnosticProbe` y añadir probes especializados solo cuando aporten evidencia no cubierta por las capas genéricas.
- [ ] Ampliar el catálogo, verificando cada patrón y requisito antes de añadirlo: Cosmos DB, Managed Redis, AKS, Functions, API Management, Azure OpenAI, Azure AI Services, Monitor, Log Analytics, Application Insights, Microsoft Graph, endpoints Entra ID y Azure DevOps.

## Empaquetado y mantenimiento

- [ ] Añadir publicación y prueba de artefactos para `win-arm64`, `linux-x64`, `linux-arm64`, `osx-x64` y `osx-arm64` cuando los runners estén disponibles.
- [ ] Añadir un workflow de publicación versionada con SemVer y comprobar que el nombre del artefacto y comando son `aznetcheck`/`aznetcheck.exe` según plataforma.
- [ ] Probar que el perfil `win-x64` y el comando de publicación documentado producen un único ejecutable funcional desde una máquina limpia.
- [ ] Mantener trimming desactivado hasta demostrar compatibilidad con serialización y dependencias; no habilitar trimming agresivo sin pruebas de publicación.
- [ ] Añadir validación automática de formato/editorconfig y análisis estático en CI, manteniendo `TreatWarningsAsErrors`.

## Futuras capacidades Azure ARM

- [ ] Diseñar un módulo Azure independiente para consultar configuración ARM con credenciales explícitas; no acoplarlo al diagnóstico de red local.
- [ ] Explorar inspección de estado de Private Endpoint, Private DNS links, acceso público, ACLs y reglas de firewall.
- [ ] Añadir el comando `aznetcheck azure inspect` solo con permisos documentados, consultas de solo lectura y tests aislados.

## Futuro explícitamente fuera de alcance

- [ ] No implementar remediación automática, cambios de DNS/firewall/NSG/rutas, escaneo de rangos/puertos, captura de paquetes, servidor web, GUI, telemetría ni base de datos sin un requisito nuevo y revisión de seguridad.
