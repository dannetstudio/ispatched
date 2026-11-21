# ispatched — ¿este host ya está parcheado contra ese CVE?

[English](README.md) · [Español](README.es.md)

Cuando sale un CVE crítico, todo sysadmin se hace la misma pregunta: **¿mi servidor ya está
parcheado?** Casi nunca alcanza con mirar el número de versión. Debian, Ubuntu y Red Hat
aplican las correcciones por *backport* sin cambiar la versión de upstream, así que
`PHP 8.1.2` puede estar corregido en un host y vulnerable en otro. Los banners se pueden
ocultar o falsificar, y el PHP que atiende tu sitio muchas veces no es el `php` que encuentra
tu shell primero.

`ispatched` responde con honestidad. Reúne la evidencia a su alcance, dice **qué tan fuerte
es esa evidencia** y nunca afirma más de lo que sabe. Empieza con **PHP2Shell**
(CVE-2026-109618 y CVE-2026-109619), y los avisos nuevos son simples archivos JSON: sumar el
próximo CVE no exige tocar código.

- Python 3.6+, solo biblioteca estándar. No hay nada que instalar en un servidor típico.
- Revisa una **URL** (cabeceras HTTP) o **la máquina donde corre** (`--server`: evidencia de
  paquetes dpkg/rpm del PHP que realmente atiende las peticiones, y si se reinició después
  de la actualización).
- Salida para personas (`text`), scripts (`json`) y CI (`sarif`), con códigos de salida para cron.
- Nunca envía un payload de explotación y nunca modifica nada del sistema.

> **Úsalo solo en sistemas propios o con permiso para probarlos.** Ver
> [Uso responsable](#uso-responsable).

## Contenido

1. [Inicio rápido](#inicio-rápido)
2. [Qué pasó: PHP2Shell](#qué-pasó-php2shell)
3. [Cómo se decide un veredicto](#cómo-se-decide-un-veredicto)
4. [Qué NO prueba ispatched](#qué-no-prueba-ispatched)
5. [Si el resultado es `potentially_vulnerable`](#si-el-resultado-es-potentially_vulnerable)
6. [Cómo extenderlo](#cómo-extenderlo)
7. [Alternativas y créditos](#alternativas-y-créditos)
8. [Contribuir, seguridad, licencia](#contribuir-seguridad-licencia)

## Inicio rápido

```sh
pip install git+https://github.com/dannetstudio/ispatched   # o clona el repositorio
python3 -m ispatched list
```

```text
PHP2Shell  PHP2Shell: remote code execution in the PHP core  (CVE-2026-109618, CVE-2026-109619)
```

Revisar uno o más sitios (un hostname sin esquema recibe `https://`):

```sh
ispatched CVE-2026-109618 https://example.com
ispatched PHP2Shell https://a.example https://b.example --format json
ispatched PHP2Shell --targets sitios.txt         # una URL por línea
```

```text
POTENTIALLY VULNERABLE (low): http://127.0.0.1:8761 → http: PHP 8.4.26 advertised: potentially vulnerable. HTTP headers cannot show backported fixes.
PATCHED (low): http://127.0.0.1:8762 → http: PHP 8.4.27 advertised; installed build not verified.
UNKNOWN (none): http://127.0.0.1:1 → request failed: [Errno 111] Connection refused
```

Revisar la máquina en la que estás (la evidencia más fuerte, porque lee la base de datos de
paquetes en vez de un banner):

```sh
ispatched PHP2Shell --server
```

```text
UNKNOWN (none): this server → No PHP serving process found
```

(Esa muestra viene de una máquina sin PHP. En un servidor web obtienes el paquete instalado,
la versión corregida con la que se comparó y un aviso si los workers no se reiniciaron
desde la actualización.)

### Opciones

| Opción | Significado |
| --- | --- |
| `ispatched list` | Muestra los avisos incluidos en el paquete. |
| `ADVISORY` | Un id de aviso o cualquier alias, p. ej. `PHP2Shell`, `CVE-2026-109618`. |
| `URL ...` | URLs u hostnames a revisar. |
| `--server` | Revisa esta máquina en lugar de (o además de) las URLs. |
| `--targets ARCHIVO` | Archivo con una URL por línea (se omiten líneas vacías y comentarios `#`). |
| `--format text\|json\|sarif` | Formato de salida. SARIF 2.1.0 entra directo en el code scanning de GitHub. |
| `--advisories DIR` | Carga avisos JSON adicionales desde `DIR` (repetible). |
| `--timeout SEGUNDOS` | Tiempo límite por operación de red, 10 por defecto (una cadena lenta de redirecciones puede tardar más en total). |
| `--workers N` | Revisiones de URL simultáneas, 5 por defecto, máximo 20. |

### Códigos de salida

| Código | Significado |
| --- | --- |
| `0` | `patched` en todos los objetivos. |
| `1` | Al menos un objetivo es `potentially_vulnerable`. |
| `2` | Error de uso (opción inválida, aviso desconocido, archivo ilegible). |
| `3` | Ningún objetivo es vulnerable, pero al menos uno es `unknown`. |

Así sirve para cron o CI: `ispatched PHP2Shell --server || avisar`.

## Qué pasó: PHP2Shell

*Todo lo de esta sección enlaza a su fuente. Las fechas son de 2026.*

- **Dos fallas en el núcleo de PHP, no en una librería.** El proyecto PHP las describe como
  [CVE-2026-109618, "RCE vía corrupción por OOM"](https://github.com/advisories/GHSA-w8hw-w9fx-j79w):
  el manejo de falta de memoria puede interrumpir a PHP cuando los datos internos de la
  petición están solo parcialmente inicializados, y la limpieza de la petición trata esos datos
  inválidos como válidos; y
  [CVE-2026-109619, "RCE vía estado global obsoleto"](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp):
  estado interno propio de la petición sobrevive después de liberar su memoria, y una
  petición posterior atendida por el mismo worker puede usarlo. Ambas pueden permitir
  ejecución remota de código sin autenticación
  ([aviso de php.net, 21 oct](https://www.php.net/archive/2026.php#2026-10-21-5)).
- **Por qué importa que sea el motor.** Los errores están en PHP mismo, así que toda
  aplicación PHP queda expuesta sin importar su código o framework. PHP indica que están en
  riesgo todas las instalaciones que atienden peticiones web (PHP-FPM, Apache con mod_php,
  php-cgi, FrankenPHP, LiteSpeed) y considera mod_php el caso más grave, con un exploit
  demostrado que se activa antes de que corra código de la aplicación
  ([php.net](https://www.php.net/archive/2026.php#2026-10-21-5)).
- **Cronología.** Las fallas se filtraron el 20 de octubre y se parchearon el 21
  ([PHP2Shell en Wikipedia](https://en.wikipedia.org/wiki/PHP2Shell);
  [análisis de Wiz](https://www.wiz.io/blog/php2shell-php-rce), que la bautizó "PHP2Shell").
- **Corregido en upstream en** 8.5.12, 8.4.27, 8.3.36 y 8.2.35. PHP 8.1 y anteriores ya no
  reciben actualizaciones de upstream; el proyecto publicó backports mínimos de código fuente
  para 7.4, 8.0 y 8.1 para quienes compilan ellos mismos
  ([php.net](https://www.php.net/archive/2026.php#2026-10-21-5)). Hay versiones afectadas desde
  la 5.4 ([Wikipedia](https://en.wikipedia.org/wiki/PHP2Shell)).
- **¿Se está explotando? Las fuentes no coinciden.** El equipo de inteligencia de amenazas de
  Amazon
  [reportó explotación](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
  y watchTowr
  [publicó un FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/) que la trata como
  activamente peligrosa. Sansec
  [informa que las pruebas de concepto públicas fallan en instalaciones por defecto](https://sansec.io/research/php2shell)
  y que por eso la explotación masiva es menos probable. `ispatched` no toma partido: la
  lectura prudente es que hace falta parchear de todos modos, y que un exploit funcional es
  cuestión de tiempo y configuración.
- **Por qué el número de versión engaña.** Las distribuciones corrigen ramas viejas con
  backports y conservan la versión de upstream. `8.1.2-1ubuntu2.28` en Ubuntu 22.04 contiene
  la corrección; un `8.1.2` compilado a mano no. `X-Powered-By: PHP/8.1.2` no distingue entre
  ambos, por eso la evidencia HTTP se considera *baja* y nunca se informa como "vulnerable",
  solo como "potencialmente vulnerable".

Referencias defensivas relacionadas: el
[NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) del NCSC neerlandés y el
[aviso del NCSC del Reino Unido](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php).

## Cómo se decide un veredicto

Cada objetivo recibe uno de tres estados, respaldado por uno o más *hallazgos* (findings),
cada uno de un *proveedor* con una *confianza*:

| Proveedor | Mira | Confianza |
| --- | --- | --- |
| `dpkg` | Paquete Debian/Ubuntu dueño del binario de PHP que atiende, comparado con la versión corregida del vendor | **alta** |
| `rpm` | Paquete de la familia RHEL dueño del binario (con epoch) | **alta** |
| `upstream` | La versión de PHP contra las versiones corregidas de upstream (no ve backports) | media |
| `http` | Cabeceras `Server` / `X-Powered-By`, siguiendo hasta 5 redirecciones http(s) | baja |

Estados: `patched`, `potentially_vulnerable`, `unknown`. A propósito no existe "vulnerable
confirmado": sin explotar la falla nadie puede confirmarlo.

Reglas, de mayor a menor fuerza: la evidencia de paquete del vendor gana a las versiones de
upstream, que ganan a las cabeceras. Si la evidencia se contradice, gana la lectura más
pesimista, salvo que un paquete del vendor (confianza alta) anula una suposición por
cabeceras. Un hallazgo `unknown` de igual o mayor confianza impide que se sostenga un
"patched" de menor confianza. `--server` además detecta si el paquete parcheado se instaló
**después** de que arrancaran los workers de PHP, porque esos workers siguen ejecutando el
código viejo: reinicia PHP-FPM o Apache.

Detalle completo y razonamiento: [docs/how-verdicts-work.md](docs/how-verdicts-work.md).

## Qué NO prueba ispatched

- Una cabecera con `PHP/8.4.27` muestra lo que el servidor *anuncia*. Puede estar falsificada
  o ser de otra capa (un proxy) distinta de la que ejecuta PHP. Por eso un `patched` por URL
  dice "installed build not verified".
- Un host sin cabecera `X-Powered-By` (lo recomendable) devuelve `unknown`. No es un defecto:
  ocultar la versión es buena práctica. Usa `--server` en el host.
- Las tablas de vendors cubren lo verificado hasta ahora (Debian 12/13, Ubuntu 14.04–26.10,
  RHEL 7/8/9). Otras distribuciones caen en una comparación con upstream o en `unknown`.
  Ver [docs/unverified-vendor-data.md](docs/unverified-vendor-data.md).
- `--server` necesita root para ver los procesos de otros usuarios (PHP-FPM suele correr como
  `www-data`). Sin root el resultado es `unknown`, con una nota que lo explica.
- La evidencia del proveedor vale solo para el build de la propia distribución. Un PHP de otra
  fuente (PPA de Sury/Ondřej, Remi, un module stream de RHEL, compilado a mano) se compara solo
  con las versiones upstream, con confianza media, y el motivo lo dice.
- Varias versiones de PHP en una misma máquina: se revisa cada proceso que atiende, y una
  instancia `unknown` vuelve `unknown` a todo el veredicto en lugar de esconderse detrás de una
  parcheada.
- No busca compromisos. Si tuviste un PHP expuesto sin parchear, revisa también tus logs y
  archivos, además de parchear.

## Si el resultado es `potentially_vulnerable`

1. **Actualiza PHP** a una versión corregida de upstream (8.2.35, 8.3.36, 8.4.27, 8.5.12) o al
   paquete parcheado de tu vendor. Para PHP 8.1 y anteriores solo sirve un backport del vendor
   o pasar a una rama con soporte.
2. **Reinicia los workers**: `systemctl restart php8.x-fpm` o recarga Apache. Un paquete
   actualizado no protege a los procesos que arrancaron antes.
3. **Si no puedes actualizar ya**, el proyecto PHP lista medidas que *reducen la exposición
   pero no vuelven segura la instalación*
   ([php.net](https://www.php.net/archive/2026.php#2026-10-21-5)):
   - `session.upload_progress.enabled=0` en `php.ini` o en el pool (no con `ini_set()` ni
     `.user.ini`) y reiniciar todos los workers. Bloquea las rutas confirmadas de
     CVE-2026-109619, no otras variantes.
   - En PHP 8.5, `fatal_error_backtraces=0`.
   - `memory_limit=-1` fijado de forma que las aplicaciones no puedan cambiarlo
     (`php_admin_value`), y un `post_max_size` bajo (8M, o 32M si necesitas subidas) para
     CVE-2026-109618. Un fallo de asignación subyacente aún puede llegar a la ruta vulnerable.
   - Imponer límites de tamaño de petición, cantidad de campos y partes multipart en el
     servidor web o proxy.
   - No uses `RLIMIT_AS` / `RLIMIT_DATA`: pueden provocar el fallo de asignación vulnerable.
4. Vuelve a ejecutar `ispatched` después.

## Cómo extenderlo

- **Un CVE nuevo** es un archivo JSON. Copia el ejemplo de
  [docs/adding-an-advisory.md](docs/adding-an-advisory.md), pruébalo con
  `ispatched --advisories ./mis-avisos NUEVO-ID --server` y envíalo como pull request.
- **Una nueva fuente de evidencia** (Alpine, cPanel/CloudLinux, Plesk, Sury/Remi, contenedores)
  es un proveedor: una función que devuelve un `Finding`. Ver
  [docs/writing-a-provider.md](docs/writing-a-provider.md).
- Las filas de vendor sin fecha `verified_on` se ignoran a propósito: datos sin verificar no
  deben producir un "patched".

## Alternativas y créditos

`ispatched` se inspiró en [openai/php2shell-checker](https://github.com/openai/php2shell-checker),
que mostró cómo podía ser un verificador para este CVE. El código de aquí está escrito desde
cero con otro diseño (avisos como datos, proveedores enchufables, niveles de confianza
honestos). También conviene conocer:

- [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell): material de referencia del NCSC neerlandés.
- [Sansec](https://sansec.io/research/php2shell): análisis y herramientas para tiendas Magento y PHP.
- El tracker de tu distribución: [Debian](https://security-tracker.debian.org/tracker/CVE-2026-109618),
  [Ubuntu](https://ubuntu.com/security/CVE-2026-109618),
  [Red Hat](https://access.redhat.com/security/cve/CVE-2026-109618).

## Contribuir, seguridad, licencia

- Las contribuciones son bienvenidas: [CONTRIBUTING.md](CONTRIBUTING.md). Lo más útil son
  datos de avisos y nuevos proveedores.
- ¿Encontraste un problema en `ispatched` mismo? Ver [SECURITY.md](SECURITY.md).
- Notas de versión: [CHANGELOG.md](CHANGELOG.md).
- Licencia Apache-2.0; ver [LICENSE](LICENSE).

### Uso responsable

`ispatched` envía una petición `HEAD` normal por URL (un `GET` solo si el servidor rechaza
`HEAD`), con un User-Agent que identifica la herramienta, y nunca envía payloads de
explotación. Aun así, úsalo solo contra sistemas propios o con permiso explícito para
probarlos. Eres responsable del uso que le des.
