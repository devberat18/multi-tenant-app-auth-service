# Auth Service – Specification & Completion Checklist

## 1. Servisin Amacı (Scope)

Auth Service; sistemdeki tüm kullanıcıların **kimlik doğrulama (authentication)**,
**erişim yetkilendirme çekirdeği (authorization / access)** ve **oturum güvenliği**
sorumluluğunu üstlenir.

Bu servis:
- Kullanıcının *kim olduğunu*
- Hangi tenant’lara üye olduğunu
- Seçili tenant’ta *hangi role / yetkilere* sahip olduğunu
cevaplayabilen **tek otoritedir**.

> Tenant oluşturma, domain, billing, site yönetimi **bu servisin scope’u değildir**.

---

## 2. Core Responsibilities

- Identity & Authentication
- Session & Token Management
- Account Lifecycle
- Verification & OTP flows
- Tenant Membership & Access Resolution
- Admin-level user moderation
- Event publishing (integration backbone)

---

## 3. Authentication (Kimlik Akışları)

### 3.1 Register
- Email + password
- Password hashing (bcrypt/argon2)
- User created event publish

### 3.2 Login
- Credential validation
- Session creation
- Access token + refresh token üretimi
- IP & User-Agent capture

### 3.3 Refresh Token
- Refresh token rotation
- Old refresh token revoke
- Reuse detection (varsa)

### 3.4 Logout
- Current session revoke

### 3.5 Logout All
- All sessions revoke (except current opsiyonel)

---

## 4. Account Management

### 4.1 Me Endpoint
- `GET /me`
- User profile summary
- Active tenant context

### 4.2 Password Change
- Authenticated user
- Old password validation

### 4.3 Account Deactivate / Delete
- Soft delete önerilir
- Tüm session’lar revoke edilir
- User deactivated event publish

---

## 5. Verification & Recovery

### 5.1 Email Verification
- Verification token / OTP send
- Confirm endpoint
- Verified flag set

### 5.2 Forgot Password
- Reset token / OTP generate
- TTL + attempt limit
- Cooldown enforcement

### 5.3 Reset Password
- Token validation
- Password update
- All sessions revoke

---

## 6. Session Security (Critical)

### 6.1 Session Model
- sessionId
- userId
- ipAddress
- userAgent
- createdAt
- lastUsedAt
- revokedAt

### 6.2 Session List
- `GET /me/sessions`
- Device-level visibility

### 6.3 Session Revoke
- Single session revoke
- Revoke all sessions

---

## 7. Tenant & Access Core (Auth Responsibility)

### 7.1 Tenant Membership
Auth, kullanıcı–tenant ilişkisini **okur ve resolve eder**.

- Membership:
  - userId
  - tenantId
  - role
  - status

### 7.2 Active Tenant Selection
- `GET /me/tenants`
- `POST /me/active-tenant`
- Active tenant token claim olarak taşınır

JWT Claims:
- `sub` → userId
- `tid` → activeTenantId
- `role` → tenant scoped role

### 7.3 Role & Permission Model

#### Roles (Minimum)
- Owner
- Admin
- Editor
- Analyst
- Viewer

#### Permission Infrastructure
- Role → permission mapping
- Allow / deny override altyapısı (MVP’de opsiyonel)
- Endpoint-level enforcement

> Auth permission **kararını üretir**, enforcement servislerde yapılır.

---

## 8. Admin Endpoints (Platform-level)

### 8.1 User List
- Pagination
- Filter (email, status)

### 8.2 Ban / Unban
- Login & token block
- All sessions revoke
- Event publish

### 8.3 Role Update
- Platform role (varsa)
- Tenant role assignment (membership üzerinden)

---

## 9. Event Publishing

Auth servisi sistemdeki diğer servisler için **source of truth event producer**’dır.

### 9.1 Events
- user.created
- user.updated
- user.email_verified
- user.password_reset
- user.deactivated
- user.banned
- session.revoked
- tenant.membership.created
- tenant.membership.updated

### 9.2 Event Payload Standard
- eventId
- eventType
- occurredAt
- actorUserId
- targetUserId
- tenantId (varsa)
- metadata

---

## 10. Non-Functional Requirements

### 10.1 Security
- Rate limit (login, otp)
- Brute-force protection
- Secure password hashing
- Token expiration policies

### 10.2 Observability
- Structured logs
- requestId / correlationId
- Auth failure reasons logged

### 10.3 Validation
- DTO validation
- Consistent error codes

---

## 11. Testing Requirements

### Unit Tests
- Token generation
- Password validation
- Permission resolve logic

### E2E Tests (Minimum)
1. Login → Refresh → Revoke
2. Forgot password → Reset
3. Active tenant selection → Guard enforcement

---

## 12. “Auth is DONE” Acceptance Criteria

Auth servisi **bitmiş kabul edilir** eğer:

- Login/refresh/logout kusursuz çalışıyorsa
- Reset password akışı güvenliyse
- Session list & revoke gerçekçi veri gösteriyorsa
- Active tenant + role token claim ile diğer servis guard’ları çalışıyorsa
- Kritik event’ler publish ediliyorsa

Bu noktadan sonra:
> Profile Service’e geçilebilir.
