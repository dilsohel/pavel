# Security Specification — PABEL SPORTS Firestore Rules

## 1. Data Invariants
1. **Catalog Integrity**: Products in `/products/{productId}` and storefront settings in `/storeConfig/public` are publicly readable by all customer devices, but ONLY verified store administrators (`isAdmin()`) may create, update, or delete them.
2. **PII Isolation**: Orders (`/orders/{orderId}`), Order Notifications (`/notifications/{notificationId}`), Admin Automation Settings (`/storeConfig/adminSettings`), Dealer Applications (`/dealers/{dealerId}`), and Contact Messages (`/messages/{messageId}`) contain customer PII (`phone`, `customerEmail`, `address`, `customerName`) or private webhook endpoints. Unauthenticated visitors and non-admin users may `create` valid order/dealer/message submissions, but ONLY verified administrators (`isAdmin()`) may read or manage `/notifications` and `/storeConfig/adminSettings`.
3. **Order Integrity**: Newly created orders must have `status == 'Pending'`, no pre-populated `lastNotifiedStatus`/`lastNotifiedAt` fields, server timestamps (`createdAt == request.time`, `updatedAt == request.time`), non-negative totals, and bounded item arrays (`items.size() >= 1 && items.size() <= 50`).
4. **Immutable Audit Fields**: `id` and `createdAt` cannot be modified after creation.
5. **No Shadow Fields**: Every collection enforces `keys().hasAll(...) && keys().hasOnly(...)` on creation and strict `affectedKeys().hasOnly(...)` on updates.
6. **Verified Admin Auth**: Admin status requires `request.auth != null && request.auth.token.email_verified == true` matching the bootstrapped owner email (`dilmohammad9011@gmail.com`) or an entry in `/admins/{request.auth.uid}`.

## 2. The "Dirty Dozen" Attack Payloads (All Must Be Denied)
1. **Unauthenticated Product Mutation**: Anonymous client attempts `setDoc('/products/ps-001', ...)` -> `PERMISSION_DENIED`.
2. **Unverified Admin Email Spoof**: User signs in with `email == 'dilmohammad9011@gmail.com'` and `email_verified == false` -> `PERMISSION_DENIED`.
3. **PII Order Scraping**: Customer attempts `getDocs('/orders')` or `getDoc('/orders/PS-2026-1041')` -> `PERMISSION_DENIED`.
4. **PII Dealer Scraping**: Customer attempts `getDocs('/dealers')` -> `PERMISSION_DENIED`.
5. **Shadow Field Injection on Order**: Visitor creates an order with extra ghost field `isPaid: true` -> `PERMISSION_DENIED`.
6. **Pre-Confirmed Order Bypass**: Visitor creates an order with `status: 'Confirmed'` or `status: 'Delivered'` -> `PERMISSION_DENIED`.
7. **Timestamp Forgery on Order**: Visitor creates an order with a client-forged `createdAt` timestamp instead of `request.time` -> `PERMISSION_DENIED`.
8. **Negative Price / Total Manipulation**: Visitor creates an order with `total: -500` or `subtotal: -100` -> `PERMISSION_DENIED`.
9. **Resource Poisoning via Oversized ID**: Client attempts `setDoc('/orders/' + 'a'.repeat(500), ...)` -> `PERMISSION_DENIED`.
10. **Invalid Path ID Characters**: Client attempts path ID with spaces or slashes (`bad id!`) -> `PERMISSION_DENIED`.
11. **Self-Privilege Escalation**: Non-admin user attempts `setDoc('/admins/' + uid, ...)` -> `PERMISSION_DENIED`.
12. **Customer Modifying Existing Order or Notification Log**: Customer attempts `updateDoc('/orders/PS-2026-1041', { status: 'Delivered' })`, reads `/storeConfig/adminSettings`, or creates/reads `/notifications` -> `PERMISSION_DENIED`.
