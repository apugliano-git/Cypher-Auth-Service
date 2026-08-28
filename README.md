# Cypher Auth Service

Cypher es un servicio de autenticación seguro y moderno construido con Spring Boot. Provee gestión de usuarios, emisión de tokens JWT asimétricos, rate limiting contra ataques de fuerza bruta y un innovador sistema de detección de anomalías geográficas (Viaje Imposible) asistido por LLM.

## 🚀 Tecnologías y Stack

- **Java 21** & **Spring Boot 3**
- **PostgreSQL 16**: Persistencia de usuarios y auditoría de accesos.
- **Redis 7**: Contadores ultra rápidos para Rate Limiting.
- **MaxMind GeoLite2**: Resolución de IPs para detección de viajes imposibles.
- **Anthropic Claude (LLM)**: Explicación inteligente de anomalías en lenguaje natural.
- **Docker & Docker Compose**: Despliegue empaquetado y reproducible.
- **Testcontainers**: Pruebas de integración reales con contenedores efímeros.

## ⚙️ Cómo Levantar el Proyecto (Docker Compose)

1. **Clonar el repositorio**:
   ```bash
   git clone <tu-repo-url>
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

## 📌 Endpoints Disponibles

- `POST /auth/register`: Registra un nuevo usuario (requiere `email` y `password` fuerte).
- `POST /auth/login`: Autentica al usuario y devuelve JWTs (`access_token` y `refresh_token`). Posee protección de Rate Limit (max 5 intentos por ventana).
- `POST /auth/refresh`: Intercambia un `refresh_token` válido por un nuevo par de tokens (Rotación).
- `GET /auth/me`: Endpoint protegido que devuelve los datos del usuario actual (requiere header `Authorization: Bearer <access_token>`).

## 🧠 Decisiones de Arquitectura

- **Firmas Asimétricas (RS256) para JWT**: A diferencia de HS256, RS256 utiliza un par de claves (pública/privada). Esto permite que el servicio Cypher sea el *único* capaz de firmar tokens (con la clave privada guardada segura en su keystore), mientras que cualquier otro microservicio puede verificar la validez del token descargando solo la clave pública, sin riesgo de que la clave simétrica se filtre o comparta.
- **Refresh Tokens Rotativos**: Los access tokens tienen una vida corta (15 min) para minimizar el impacto de un robo. Los refresh tokens duran días, pero al ser usados se "rotan" (se emite uno nuevo y el anterior se invalida). Si un atacante roba un refresh token y lo usa, la reutilización será detectada, mitigando el riesgo de robo de sesión persistente.
- **Rate Limiting con Redis**: En lugar de saturar PostgreSQL contando intentos fallidos de login por IP o Email, se usa Redis. Sus operaciones atómicas en memoria (`INCR`, `EXPIRE`) permiten limitar ráfagas de miles de requests por segundo con latencias de un solo dígito de milisegundos.
- **Detección de Anomalías Asíncrona**: La validación de salto geográfico delega la explicación en lenguaje natural a un LLM. Para evitar que la latencia de la API del LLM penalice el tiempo de respuesta del Login, el chequeo se realiza en un hilo en background (`@Async`), actualizando el registro de auditoría a posteriori.
