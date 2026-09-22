//! P2 — controller identity lifecycle: registration tokens, bearer
//! credentials, authentication, rotation, revocation.
//!
//! Secret handling (I-7 / RFC §13):
//! - Plaintext secrets exist only at issue time and in caller memory.
//! - `Debug` is redacted; there is intentionally no `Display` and no `Serialize`.
//! - Only SHA-256 verifiers are persisted — plaintext is never recoverable
//!   from store state (no reversible encryption, no recovery path).
//! - Secrets are compared only via their full SHA-256 verifier used as an
//!   exact map key: no prefix/partial/case/whitespace-insensitive matching.

use std::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::clock::Clock;
use crate::core::GatewayCore;
use crate::id::{AccountId, ControllerId};
use crate::proto::{ErrorCode, TransportError};
use crate::store::*;

/// Registration token TTL — RFC: ≤ 15 minutes.
pub const REGISTRATION_TOKEN_TTL_MS: u64 = 15 * 60 * 1000;

// ---------- secret types ----------

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("OS CSPRNG");
    hex::encode(b)
}

fn random_hex32() -> String {
    random_hex(32) // 256-bit — secrets (RFC §6)
}

fn random_hex16() -> String {
    random_hex(16) // 128-bit — non-secret identifiers (RFC §7 table)
}

fn verifier_of(secret: &str) -> Verifier {
    Verifier(hex::encode(Sha256::digest(secret.as_bytes())))
}

macro_rules! secret_type {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        /// Plaintext is held only in memory; Debug is redacted; no Display,
        /// no Serialize — accidental formatting cannot leak the secret.
        #[derive(Clone)]
        pub struct $name(String);

        impl $name {
            /// 256-bit CSPRNG secret with the documented wire prefix.
            pub fn generate() -> Self {
                Self(format!("{}{}", $prefix, random_hex32()))
            }
            /// Parse a presented secret. Strict shape — anything else is
            /// malformed, not merely "unknown".
            pub fn parse(presented: &str) -> Result<Self, TransportError> {
                let hex_part = presented.strip_prefix($prefix).ok_or_else(|| {
                    TransportError::new(ErrorCode::MalformedCredential, "malformed credential")
                })?;
                let valid = hex_part.len() == 64 && hex_part.bytes().all(|b| b.is_ascii_hexdigit());
                if !valid {
                    return Err(TransportError::new(
                        ErrorCode::MalformedCredential,
                        "malformed credential",
                    ));
                }
                Ok(Self(presented.to_string()))
            }
            /// The only sanctioned way to read the plaintext — for issuing it
            /// to its owner exactly once, or placing it on the wire.
            pub fn expose(&self) -> &str {
                &self.0
            }
            pub(crate) fn verifier(&self) -> Verifier {
                verifier_of(&self.0)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(REDACTED)"))
            }
        }
    };
}

secret_type!(
    RegistrationToken,
    "reg_",
    "Single-use account-bound bootstrap token (≤15 min TTL)."
);
secret_type!(
    ControllerCredential,
    "ctrlk_",
    "Long-term controller bearer credential (SHA-256 verifier stored)."
);

// ---------- authenticated principal ----------

/// Proof of authentication. Identity fields derive ONLY from the validated
/// credential's stored record — never from caller-supplied request fields.
/// Future /v1 handlers use this principal directly; nothing else grants
/// controller authority, and it grants no SSH/exec/target authority (I-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedController {
    account_id: AccountId,
    controller_id: ControllerId,
}

impl AuthenticatedController {
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
    pub fn controller_id(&self) -> &ControllerId {
        &self.controller_id
    }
}

// ---------- auth core ----------

pub struct ControllerAuth<S: IdentityStore, C: Clock> {
    store: Arc<S>,
    clock: C,
}

impl<S: IdentityStore, C: Clock> ControllerAuth<S, C> {
    pub fn new(store: Arc<S>, clock: C) -> Self {
        Self { store, clock }
    }

    /// Issue a single-use registration token bound to `account` (console-side
    /// operation). Plaintext is returned exactly once — only the verifier is
    /// persisted.
    pub fn issue_registration_token(
        &self,
        account: &AccountId,
    ) -> Result<RegistrationToken, TransportError> {
        let token = RegistrationToken::generate();
        self.store
            .put_registration_token(RegistrationTokenRecord {
                verifier: token.verifier(),
                account_id: account.clone(),
                expires_unix_ms: self.clock.unix_ms() + REGISTRATION_TOKEN_TTL_MS,
                created_unix_ms: self.clock.unix_ms(),
            })
            .map_err(store_err)?;
        Ok(token)
    }

    /// Consume a registration token → new controller identity + bearer
    /// credential (returned once). Atomic per the store contract: two racing
    /// consumers cannot both succeed.
    ///
    /// Re-registration: if the account's existing controller is Revoked, the
    /// new controller replaces the binding (new identity — never resurrected).
    /// If it is Active, registration fails closed (one controller/account).
    pub fn register(
        &self,
        core: &GatewayCore<C>,
        presented: &str,
    ) -> Result<(AuthenticatedController, ControllerCredential), TransportError> {
        let token = RegistrationToken::parse(presented)?;
        let rec = match self
            .store
            .take_registration_token(&token.verifier(), self.clock.unix_ms())
            .map_err(store_err)?
        {
            TokenTake::Missing => {
                return Err(TransportError::new(
                    ErrorCode::InvalidCredential,
                    "unknown registration token",
                ))
            }
            TokenTake::AlreadyConsumed => {
                return Err(TransportError::new(
                    ErrorCode::ConsumedRegistrationToken,
                    "registration token already used",
                ))
            }
            TokenTake::Expired => {
                return Err(TransportError::new(
                    ErrorCode::ExpiredRegistrationToken,
                    "registration token expired",
                ))
            }
            TokenTake::Consumed(rec) => rec,
        };

        let controller_id = ControllerId::new(format!("ctl_{}", random_hex16()));
        let cred = ControllerCredential::generate();
        let record = ControllerRecord {
            controller_id: controller_id.clone(),
            account_id: rec.account_id.clone(),
            cred_verifier: cred.verifier(),
            status: ControllerStatus::Active,
            created_unix_ms: self.clock.unix_ms(),
            rotated_unix_ms: None,
            revoked_unix_ms: None,
        };

        // Atomic one-active-per-account enforcement lives in the store.
        self.store.insert_controller(record).map_err(|e| match e {
            StoreError::AccountHasActiveController => TransportError::new(
                ErrorCode::AccountHasController,
                "account already has an active controller",
            ),
            other => store_err(other),
        })?;

        // Bind in the P1 work core. When the prior binding is a revoked
        // controller this replaces it; register_controller's own strictness
        // is bypassed only via the dedicated replace path.
        let prior = core.account_controller(&rec.account_id);
        let bind = match prior {
            Some(old) if old != controller_id => {
                core.replace_account_controller(&rec.account_id, &controller_id)
            }
            _ => core.register_controller(&controller_id, &rec.account_id),
        };
        if let Err(e) = bind {
            // Compensate: never leave a credential for an unbound controller.
            let _ = self.store.set_status(
                &controller_id,
                ControllerStatus::Revoked,
                self.clock.unix_ms(),
            );
            return Err(e);
        }

        tracing::info!(%controller_id, account = %rec.account_id, "controller registered");
        Ok((
            AuthenticatedController {
                account_id: rec.account_id,
                controller_id,
            },
            cred,
        ))
    }

    /// Bearer → authenticated principal. The credential alone determines
    /// identity; no request field can widen or redirect it.
    pub fn authenticate(&self, presented: &str) -> Result<AuthenticatedController, TransportError> {
        Ok(self.resolve(presented)?.0)
    }

    /// Re-check that a previously authenticated controller is still Active.
    /// Closes the authenticate→(gap)→deliver/respond TOCTOU (F-07): a
    /// mid-poll or post-auth revocation must take effect before further
    /// work is delivered or completed.
    pub fn ensure_active(&self, id: &ControllerId) -> Result<(), TransportError> {
        let Some(rec) = self.store.controller(id) else {
            return Err(TransportError::new(
                ErrorCode::UnknownController,
                "unknown controller",
            ));
        };
        match rec.status {
            ControllerStatus::Active => Ok(()),
            ControllerStatus::Revoked => Err(TransportError::new(
                ErrorCode::RevokedController,
                "controller revoked",
            )),
        }
    }

    /// Resolve a presented credential to (principal, verifier) — the verifier
    /// is needed by `rotate` so the atomic swap can prove the presented
    /// credential is still the live one.
    fn resolve(
        &self,
        presented: &str,
    ) -> Result<(AuthenticatedController, Verifier), TransportError> {
        let cred = ControllerCredential::parse(presented)?;
        let verifier = cred.verifier();
        let Some(rec) = self.store.controller_by_verifier(&verifier) else {
            return Err(TransportError::new(
                ErrorCode::InvalidCredential,
                "invalid credential",
            ));
        };
        match rec.status {
            ControllerStatus::Active => Ok((
                AuthenticatedController {
                    account_id: rec.account_id,
                    controller_id: rec.controller_id,
                },
                verifier,
            )),
            ControllerStatus::Revoked => Err(TransportError::new(
                ErrorCode::RevokedController,
                "controller revoked",
            )),
        }
    }

    /// Bind an authenticated principal into the P1 work core. Idempotent.
    ///
    /// The identity store is durable but the work core is memory-only: after
    /// a Gateway restart, the first authenticated poll must re-establish the
    /// account→controller binding. This is that path — it binds only what the
    /// credential already proved, so it cannot widen authority. If the account
    /// is bound to a DIFFERENT controller in the work core, fails closed
    /// (the store's one-active-per-account rule should make this unreachable).
    pub fn bind(
        &self,
        core: &GatewayCore<C>,
        principal: &AuthenticatedController,
    ) -> Result<(), TransportError> {
        match core.account_controller(principal.account_id()) {
            Some(existing) if existing == *principal.controller_id() => Ok(()),
            Some(_) => Err(TransportError::new(
                ErrorCode::WrongAccount,
                "account bound to a different controller",
            )),
            None => core.register_controller(principal.controller_id(), principal.account_id()),
        }
    }

    /// Self-service rotation: present the current credential, receive a new
    /// one. The swap is atomic — old credential dies exactly as the new one
    /// is issued (RFC: immediate invalidation, no overlap).
    pub fn rotate(&self, presented: &str) -> Result<ControllerCredential, TransportError> {
        let (principal, presented_verifier) = self.resolve(presented)?;
        let new_cred = ControllerCredential::generate();
        self.store
            .rotate_credential(
                principal.controller_id(),
                &presented_verifier,
                new_cred.verifier(),
                self.clock.unix_ms(),
            )
            .map_err(|e| match e {
                StoreError::UnknownController => {
                    TransportError::new(ErrorCode::UnknownController, "unknown controller")
                }
                StoreError::ControllerNotActive => {
                    TransportError::new(ErrorCode::RevokedController, "controller revoked")
                }
                // Lost a rotation race: the presented credential is no longer
                // live, so from the caller's view it is simply invalid.
                StoreError::StaleCredential => {
                    TransportError::new(ErrorCode::InvalidCredential, "invalid credential")
                }
                other => store_err(other),
            })?;
        tracing::info!(controller = %principal.controller_id(), "credential rotated");
        Ok(new_cred)
    }

    /// Self-revocation via the presented credential.
    pub fn revoke(&self, presented: &str) -> Result<(), TransportError> {
        let principal = self.authenticate(presented)?;
        self.set_revoked(principal.controller_id())
    }

    /// Administrative revocation by identity (console path).
    pub fn revoke_controller(&self, id: &ControllerId) -> Result<(), TransportError> {
        self.set_revoked(id)
    }

    fn set_revoked(&self, id: &ControllerId) -> Result<(), TransportError> {
        self.store
            .set_status(id, ControllerStatus::Revoked, self.clock.unix_ms())
            .map_err(|e| match e {
                StoreError::UnknownController => {
                    TransportError::new(ErrorCode::UnknownController, "unknown controller")
                }
                other => store_err(other),
            })?;
        tracing::info!(controller = %id, "controller revoked");
        Ok(())
    }
}

fn store_err(e: StoreError) -> TransportError {
    TransportError::new(ErrorCode::StoreFailure, format!("{e:?}"))
}
