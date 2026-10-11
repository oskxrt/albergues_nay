# Despliegue privado — Control de Albergues Nayarit

La página pública de GitHub Pages **NO proporciona control de acceso**. La solución preparada aquí usa un **Cloudflare Worker + Cloudflare Access** para autenticar, y GitHub como almacén de `data/albergues.json`. Solo el correo administrador puede escribir.

## Antes de publicar
1. **Haz privado** `oskxrt/albergues_nay` o crea una copia privada. Actualmente la versión antigua ya contiene datos operativos en un repositorio público: cambiarlo a privado evita nuevas consultas públicas, pero no deshace copias previamente obtenidas.
2. Desactiva GitHub Pages: Settings → Pages → despublicar.
3. Crea una aplicación **Self-hosted** en Cloudflare Zero Trust → Access → Applications para el dominio del Worker. Política **Allow** limitada a los correos autorizados; configura MFA.
4. Despliega el Worker desde este repositorio (Cloudflare Workers → Create → Import a repository, o Wrangler CLI).
5. Configura variables `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, `ADMIN_EMAIL` y un **secret** `GITHUB_TOKEN` (token fine-grained de GitHub, restringido a este repositorio con permiso de Contents Read/Write). Nunca introduzcas el token en el HTML, el repositorio o chats.
6. Usa **únicamente** el dominio Worker protegido por Access, no el anterior `github.io`.

El Worker valida criptográficamente el JWT de Cloudflare Access usando las claves JWKS del equipo, así como issuer, audience y vencimiento. `GET /api/me` devuelve el rol; `GET /api/state` lee los registros; `PUT /api/state` permite escribir únicamente al administrador y usa control de versión (SHA) para evitar sobreescritura accidental.

**Limitaciones:** este repositorio y este código por sí solos NO activan Cloudflare Access ni cambian la visibilidad del repositorio. El acceso restringido no está habilitado hasta completar esos pasos.

**Seguridad de datos:** la aplicación sirve contactos y ubicaciones solo detrás del Access configurado. Los PDF que exportes contienen la información que hayas autorizado compartir. Haz respaldos periódicos de `data/albergues.json`.
