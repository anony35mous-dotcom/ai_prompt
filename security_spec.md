# Security Specification (`prompts` Collection)

## Application Access Model
This application ("나의 AI 프롬프트 창고") provides public read-only browsing, search, category filtering, detail view, and copy functionality for guests, while restricting all write mutations (`create`, `update`, `delete`) exclusively to the verified administrator account (`anony35mous@gmail.com`).

## 1. Data Invariants
1. Every document in `prompts` MUST contain exactly four keys: `title`, `category`, `content`, `createdAt`.
2. `title` must be a non-empty string with length `1..100`.
3. `category` must strictly belong to the allowlist: `["사진 합성", "스타일 변환", "캐릭터·포스터"]`.
4. `content` must be a non-empty string with length `1..10000` (supporting long prompts over 1,000 characters while preventing resource exhaustion).
5. `createdAt` must equal `request.time` on creation and remain immutable on update.
6. Document IDs (`promptId`) must match `^[a-zA-Z0-9_\-]+$` and be at most 128 characters.
7. Only authenticated users with `request.auth.token.email == "anony35mous@gmail.com"` AND `request.auth.token.email_verified == true` may create, update, or delete documents.

## 2. Adversarial "Dirty Dozen" Payloads (Expected: PERMISSION_DENIED)
1. **Unauthenticated Create**: Guest attempting `addDoc` -> denied (`isAdmin()` false).
2. **Non-Admin Authenticated Create**: Different Google user attempting `addDoc` -> denied (`email != 'anony35mous@gmail.com'`).
3. **Unverified Admin Email Spoof**: Token with `email == 'anony35mous@gmail.com'` and `email_verified == false` -> denied.
4. **Unauthenticated Update/Delete**: Guest attempting `updateDoc` or `deleteDoc` -> denied.
5. **Shadow Field Injection by Admin**: `{ title: "A", category: "사진 합성", content: "B", createdAt: serverTimestamp(), isAdmin: true }` -> denied (`hasOnly` check).
6. **Missing Required Field (`content`)**: `{ title: "A", category: "사진 합성", createdAt: serverTimestamp() }` -> denied.
7. **Invalid Category Enum**: `{ title: "A", category: "기타", content: "B", createdAt: serverTimestamp() }` -> denied.
8. **Oversized Title (>100 chars)** or **Empty Title** -> denied.
9. **Oversized Content (>10000 chars)** or **Empty Content** -> denied.
10. **Spoofed Past Timestamp on Create**: `createdAt != request.time` -> denied.
11. **Mutating `createdAt` on Update**: `updateDoc(ref, { createdAt: serverTimestamp() })` -> denied.
12. **Poisoned Document ID**: `setDoc(doc(db, "prompts", "bad id with spaces!"), { ... })` -> denied.
