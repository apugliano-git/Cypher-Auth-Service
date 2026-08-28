# Cypher Auth Service

Cypher es un servicio centralizado de identidad y autorización (OAuth2/OIDC) diseñado como un módulo base de seguridad reutilizable para múltiples proyectos personales. Su objetivo es unificar la autenticación y el control de acceso: emite y valida tokens JWT firmados asimétricamente, permitiendo que cualquier otra aplicación (cliente OIDC estándar) delegue el proceso de login en lugar de reimplementarlo desde cero. Es un proyecto de aprendizaje continuo donde cada pieza se construyó primero entendiendo los fundamentos conceptuales de la seguridad en sistemas distribuidos antes de escribir código.

## Tecnologías y Stack

- **Java 21** & **Spring Boot 3**
- **PostgreSQL 16**: Persistencia de usuarios y auditoría de accesos.
- **Redis 7**: Contadores en memoria para Rate Limiting.
- **MaxMind GeoLite2**: Resolución de IPs para detección de viajes imposibles.
- **Anthropic Claude (LLM)**: Explicación de anomalías en lenguaje natural.
- **Docker & Docker Compose**: Despliegue empaquetado y reproducible.
- **Testcontainers**: Pruebas de integración con contenedores efímeros.

## Cómo Levantar el Proyecto (Docker Compose)

1. **Clonar el repositorio**:
   ```bash
   git clone https://github.com/apugliano-git/Cypher-Auth-Service
   cd Cypher_Auth_Service
   ```

2. **Configurar el entorno**:
   Copiá el archivo de ejemplo y completá las variables:
   ```bash
   cp .env.example .env
   ```
   Asegurate de tener el keystore (`cypher-keystore.p12`) y la base de datos de MaxMind (`GeoLite2-City.mmdb`) en la carpeta `secrets/`.

3. **Levantar los servicios**:
   ```bash
   docker compose up -d
   ```
   Esto levantará `postgres`, `redis` y compilará la aplicación `cypher` usando un Dockerfile multi-stage, exponiéndola en el puerto `8080`.

## Endpoints Disponibles

- `POST /auth/register`: Registra un nuevo usuario (requiere `email` y `password` fuerte).
- `POST /auth/login`: Autentica al usuario y devuelve JWTs (`access_token` y `refresh_token`). Posee protección de Rate Limit (max 5 intentos por ventana).
- `POST /auth/refresh`: Intercambia un `refresh_token` válido por un nuevo par de tokens (Rotación).
- `GET /auth/me`: Endpoint protegido que devuelve los datos del usuario actual (requiere header `Authorization: Bearer <access_token>`).

## Decisiones de Arquitectura

- **Firmas Asimétricas (RS256) para JWT**: A diferencia de HS256, RS256 utiliza un par de claves (pública/privada). Esto permite que el servicio Cypher sea el único capaz de firmar tokens (con la clave privada guardada en su keystore), mientras que cualquier otro microservicio puede verificar la validez del token descargando solo la clave pública, sin riesgo de que la clave simétrica se filtre o comparta.
- **Refresh Tokens Rotativos**: Los access tokens tienen un tiempo de expiración de 15 minutos para minimizar el impacto en caso de compromiso. Los refresh tokens tienen mayor duración, pero al ser utilizados se rotan (se emite uno nuevo y el anterior se invalida). Si un refresh token comprometido es reutilizado, la rotación permite detectar la anomalía y mitigar el acceso no autorizado.
- **Rate Limiting con Redis**: En lugar de delegar el conteo de intentos fallidos de login por IP o Email a PostgreSQL, se utiliza Redis. Sus operaciones atómicas en memoria (`INCR`, `EXPIRE`) permiten limitar peticiones concurrentes con baja latencia.
- **Detección de Anomalías Asíncrona**: La validación de salto geográfico delega la explicación en lenguaje natural a un LLM. Para evitar que la latencia del proveedor externo bloquee el tiempo de respuesta del Login, el llamado se realiza en un hilo secundario (`@Async`), actualizando el registro de auditoría posteriormente.
