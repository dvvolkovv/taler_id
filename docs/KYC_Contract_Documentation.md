# KYC Attestation Contract — Документация

**Адрес:** `5ESHygc8MtXzDC1M7njq7Gke4k27supzujpcTZjavvEHywJD`
**Code hash:** `0x5e04519c4a57df5a2ddaac0d6a8a8768c1d71f131f01d598e4275ff03ae514e4`
**Сеть:** Taler testnet `wss://node.dev.gsmsoft.eu/`
**Язык:** ink! v5 (Rust/Wasm)
**Версия контракта:** 1.0.0

---

## 1. Как открыть контракт в браузере

### Вариант A: Contracts UI (рекомендуется)

1. Открыть: **https://contracts-ui.substrate.io/**
2. В левом верхнем углу нажать на сеть → **Add Custom Endpoint**
3. Ввести: `wss://node.dev.gsmsoft.eu/`
4. Нажать **Connect**
5. В меню слева → **Add Contract**
6. Выбрать **Use On-Chain Contract Address**
7. Ввести адрес: `5ESHygc8MtXzDC1M7njq7Gke4k27supzujpcTZjavvEHywJD`
8. Загрузить ABI файл: `/home/dvolkov/kyc-attestation/target/ink/kyc_attestation.json`
   *(скопировать с сервера или использовать содержимое из раздела 5 ниже)*
9. Нажать **Add Contract**

После этого будет доступен интерфейс для вызова всех методов контракта.

### Вариант B: Polkadot.js Apps

1. Открыть: **https://polkadot.js.org/apps/**
2. Вверху слева кликнуть на логотип → **DEVELOPMENT** → **Custom**
3. Ввести: `wss://node.dev.gsmsoft.eu/` → **Switch**
4. В меню: **Developer** → **Contracts**
5. Нажать **Add an existing contract**
6. **Contract address:** `5ESHygc8MtXzDC1M7njq7Gke4k27supzujpcTZjavvEHywJD`
7. **Contract name:** `KycAttestation`
8. Загрузить ABI: `kyc_attestation.json`
9. **Save**

---

## 2. Методы контракта

### 2.1 `get_verification` — Чтение KYC статуса

**Тип:** read-only (не требует транзакции, бесплатно)
**Selector:** `0x1fec2daf`

**Аргументы:**
| Аргумент | Тип | Описание |
|----------|-----|----------|
| `taler_id_hash` | `[u8; 32]` | SHA-256 хэш внутреннего UUID пользователя |

**Возвращает:** `Option<(u8, u64, u8, bool)>` или `None`
| Поле | Тип | Описание |
|------|-----|----------|
| `kyc_status` | u8 | 0=нет, 1=pending, 2=verified, 3=rejected |
| `kyc_timestamp` | u64 | UNIX timestamp верификации |
| `kyb_status` | u8 | 0=нет, 1=verified (для бизнесов) |
| `is_active` | bool | false после GDPR удаления |

**Пример результата:**
```
Some((2, 1740000000, 0, true))
 ↑       ↑            ↑   ↑
KYC     timestamp    KYB  active
verified
```

---

### 2.2 `get_attester` — Адрес аттестора

**Тип:** read-only
**Selector:** `0x8270c790`
**Аргументы:** нет
**Возвращает:** `AccountId` — текущий аккаунт с правом записи

Текущее значение: `5EZS5Lp5bdPdvcNfzaiFNjsTbtK78qWjCZVwACZFCEWVwRRp`

---

### 2.3 `attest_verification` — Записать KYC статус

**Тип:** write (требует транзакцию от аттестора)
**Selector:** `0xfc067f95`

**Аргументы:**
| Аргумент | Тип | Описание |
|----------|-----|----------|
| `taler_id_hash` | `[u8; 32]` | SHA-256 хэш UUID пользователя |
| `kyc_status` | u8 | 2 = Verified, 3 = Rejected |
| `kyc_timestamp` | u64 | UNIX timestamp (секунды) |

**Права:** только `attester`
**Событие при успехе:** `VerificationAttested { taler_id_hash, kyc_status, kyc_timestamp }`

---

### 2.4 `attest_kyb` — Записать KYB статус

**Тип:** write
**Selector:** `0x659dabb3`

**Аргументы:**
| Аргумент | Тип | Описание |
|----------|-----|----------|
| `taler_id_hash` | `[u8; 32]` | SHA-256 хэш UUID тенанта |
| `verified` | bool | true = верифицировано |

**Права:** только `attester`
**Событие:** `KybAttested { taler_id_hash, verified }`

---

### 2.5 `revoke_verification` — Отозвать верификацию

**Тип:** write
**Selector:** `0x5d666069`

**Аргументы:**
| Аргумент | Тип | Описание |
|----------|-----|----------|
| `taler_id_hash` | `[u8; 32]` | SHA-256 хэш UUID пользователя |

**Результат:** устанавливает `is_active = false`
**Ошибка:** `NotFound` если хэш не существует
**Событие:** `VerificationRevoked { taler_id_hash }`

---

### 2.6 `transfer_attester` — Передать права аттестора

**Тип:** write
**Selector:** `0x6a97cdc2`

**Аргументы:**
| Аргумент | Тип | Описание |
|----------|-----|----------|
| `new_attester` | `AccountId` | Новый аккаунт-аттестор |

**Права:** только текущий `attester`

---

## 3. События (Events)

| Событие | Indexed поле | Остальные поля |
|---------|-------------|----------------|
| `VerificationAttested` | `taler_id_hash` | `kyc_status`, `kyc_timestamp` |
| `VerificationRevoked` | `taler_id_hash` | — |
| `KybAttested` | `taler_id_hash` | `verified` |

---

## 4. Коды ошибок

| Код | Значение |
|-----|----------|
| `Unauthorized` | Вызывающий ≠ attester (только чтение разрешено всем) |
| `NotFound` | Хэш не найден в `records` (только в `revoke_verification`) |

---

## 5. Как вычислить `taler_id_hash` для запроса

Контракт хранит `SHA-256(userId)`, где `userId` — внутренний UUID пользователя в базе Taler ID.

```javascript
// JavaScript (браузер или Node.js)
const userId = "550e8400-e29b-41d4-a716-446655440000"; // UUID из БД Taler ID
const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(userId));
const hashArray = Array.from(new Uint8Array(hashBuffer));
const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
// → "a3f1c2..." (64 hex символа = 32 байта)
```

```bash
# Linux/Mac
echo -n "550e8400-e29b-41d4-a716-446655440000" | sha256sum
```

```python
import hashlib
user_id = "550e8400-e29b-41d4-a716-446655440000"
h = hashlib.sha256(user_id.encode()).hexdigest()
print(h)  # a3f1c2...
```

В Contracts UI хэш вводится как массив байт: `[163, 241, 194, ...]` (32 числа от 0 до 255).

---

## 6. REST API Taler ID для on-chain данных

Taler ID предоставляет endpoint, который автоматически вычисляет хэш и запрашивает контракт:

```
GET http://138.124.61.221:3000/kyc/on-chain/{userId}
Authorization: Bearer <jwt_token>
```

**Ответ (пользователь верифицирован):**
```json
{
  "talerId": "550e8400-e29b-41d4-a716-446655440000",
  "onChain": {
    "kycStatus": 2,
    "kycTimestamp": 1740000000,
    "kybStatus": 0,
    "isActive": true
  },
  "statusLabel": "Verified"
}
```

**Ответ (нет записи):**
```json
{
  "statusCode": 404,
  "message": "No on-chain record found for this user"
}
```

---

## 7. Как тестировать методы через Contracts UI

### Чтение (free call)

1. Открыть контракт в Contracts UI
2. Выбрать **Read** → `get_attester`
3. Нажать **Read** → результат: `5EZS5Lp5bdPdvcNfzaiFNjsTbtK78qWjCZVwACZFCEWVwRRp`

Для `get_verification`:
1. Выбрать **Read** → `get_verification`
2. В поле `taler_id_hash` ввести массив 32 байт, например: `[1, 0, 0, 0, ..., 0]`
3. Нажать **Read** → вернёт `None` (если такой хэш не записан)

### Запись (требует подключённый кошелёк)

1. В Contracts UI подключить аккаунт аттестора
   - Импортировать seed фразу в Polkadot.js Extension:
     `frozen lady season ride legal volume kingdom husband dilemma milk bench north`
2. Выбрать **Execute** → нужный метод
3. Указать аргументы
4. Нажать **Call** → подтвердить транзакцию

---

## 8. Структура хранилища контракта

```rust
pub struct KycRecord {
    pub kyc_status: u8,       // KYC статус
    pub kyc_timestamp: u64,   // Когда верифицирован
    pub kyb_status: u8,       // KYB статус (для бизнесов)
    pub is_active: bool,       // false после GDPR-удаления
}

// Хранилище:
records: Mapping<[u8; 32], KycRecord>
//               ↑
//           SHA-256(userId) — никаких персональных данных on-chain!
```

**GDPR-совместимость:** Записи содержат только хэш и числовые статусы. Имена, email, паспорта — нигде в блокчейне.

---

## 9. ABI файл (для импорта в Contracts UI)

Файл: `/home/dvolkov/kyc-attestation/target/ink/kyc_attestation.json`

Скачать с сервера:
```bash
scp dvolkov@138.124.61.221:/home/dvolkov/kyc-attestation/target/ink/kyc_attestation.json .
```

---

## 10. Полный исходный код

**Файл:** `/home/dvolkov/kyc-attestation/src/lib.rs`

```rust
#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod kyc_attestation {
    use ink::storage::Mapping;

    #[derive(Debug, Clone, Default, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
    pub struct KycRecord {
        pub kyc_status: u8,
        pub kyc_timestamp: u64,
        pub kyb_status: u8,
        pub is_active: bool,
    }

    #[ink(event)]
    pub struct VerificationAttested {
        #[ink(topic)] taler_id_hash: [u8; 32],
        kyc_status: u8,
        kyc_timestamp: u64,
    }

    #[ink(event)]
    pub struct VerificationRevoked {
        #[ink(topic)] taler_id_hash: [u8; 32],
    }

    #[ink(event)]
    pub struct KybAttested {
        #[ink(topic)] taler_id_hash: [u8; 32],
        verified: bool,
    }

    #[ink(storage)]
    pub struct KycAttestation {
        attester: AccountId,
        records: Mapping<[u8; 32], KycRecord>,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode, scale_info::TypeInfo)]
    pub enum Error { Unauthorized, NotFound }

    pub type Result<T> = core::result::Result<T, Error>;

    impl KycAttestation {
        // Конструктор: deployer становится attester
        #[ink(constructor)]
        pub fn new() -> Self {
            Self { attester: Self::env().caller(), records: Mapping::default() }
        }

        // Записать KYC результат (только attester)
        #[ink(message)]
        pub fn attest_verification(&mut self, taler_id_hash: [u8; 32],
            kyc_status: u8, kyc_timestamp: u64) -> Result<()> {
            self.ensure_attester()?;
            let mut r = self.records.get(taler_id_hash).unwrap_or_default();
            r.kyc_status = kyc_status;
            r.kyc_timestamp = kyc_timestamp;
            r.is_active = true;
            self.records.insert(taler_id_hash, &r);
            self.env().emit_event(VerificationAttested { taler_id_hash, kyc_status, kyc_timestamp });
            Ok(())
        }

        // Записать KYB результат для бизнеса (только attester)
        #[ink(message)]
        pub fn attest_kyb(&mut self, taler_id_hash: [u8; 32], verified: bool) -> Result<()> {
            self.ensure_attester()?;
            let mut r = self.records.get(taler_id_hash).unwrap_or_default();
            r.kyb_status = if verified { 1 } else { 0 };
            r.is_active = true;
            self.records.insert(taler_id_hash, &r);
            self.env().emit_event(KybAttested { taler_id_hash, verified });
            Ok(())
        }

        // GDPR: отозвать верификацию (is_active = false)
        #[ink(message)]
        pub fn revoke_verification(&mut self, taler_id_hash: [u8; 32]) -> Result<()> {
            self.ensure_attester()?;
            let mut r = self.records.get(taler_id_hash).ok_or(Error::NotFound)?;
            r.is_active = false;
            self.records.insert(taler_id_hash, &r);
            self.env().emit_event(VerificationRevoked { taler_id_hash });
            Ok(())
        }

        // Читать KYC/KYB статус (публично, бесплатно)
        #[ink(message)]
        pub fn get_verification(&self, taler_id_hash: [u8; 32]) -> Option<(u8, u64, u8, bool)> {
            self.records.get(taler_id_hash)
                .map(|r| (r.kyc_status, r.kyc_timestamp, r.kyb_status, r.is_active))
        }

        // Передать права аттестора
        #[ink(message)]
        pub fn transfer_attester(&mut self, new_attester: AccountId) -> Result<()> {
            self.ensure_attester()?;
            self.attester = new_attester;
            Ok(())
        }

        // Узнать текущего аттестора
        #[ink(message)]
        pub fn get_attester(&self) -> AccountId { self.attester }

        fn ensure_attester(&self) -> Result<()> {
            if self.env().caller() == self.attester { Ok(()) }
            else { Err(Error::Unauthorized) }
        }
    }
}
```
