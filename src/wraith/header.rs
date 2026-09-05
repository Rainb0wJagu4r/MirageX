use std::io::{Read, Write};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::PqcSuite;
use crate::wraith::{WraithError, CURRENT_VERSION, MAGIC_BYTES};

pub const HEADER_SIZE: usize = 80;

pub const MIN_ARGON2_M_COST: u32 = 8; // 8 KiB minimum
// Security hardening (AUDIT.md M1): bounds cap the work factor an unauthenticated,
// attacker-crafted header can force on the decrypting machine (Argon2 runs BEFORE
// any authenticated check). Worst case is now ~1 GiB RAM x 10 iterations, bounded
// to a few seconds instead of hours.
pub const MAX_ARGON2_M_COST: u32 = 1024 * 1024; // 1 GiB maximum (in KiB)
pub const MIN_ARGON2_T_COST: u32 = 1;
pub const MAX_ARGON2_T_COST: u32 = 10;
pub const MIN_ARGON2_P_COST: u32 = 1;
pub const MAX_ARGON2_P_COST: u32 = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithHeader {
    pub version: u8,
    pub suite: PqcSuite,
    pub salt: [u8; 32],
    pub uuid: [u8; 16],
    pub chunk_size: u32,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub flags: u32,
}

impl WraithHeader {
    pub fn new<R: RngCore + CryptoRng>(
        suite: PqcSuite,
        chunk_size: u32,
        argon2_m_cost: u32,
        argon2_t_cost: u32,
        argon2_p_cost: u32,
        rng: &mut R,
    ) -> Self {
        let mut salt = [0u8; 32];
        let mut uuid = [0u8; 16];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut uuid);

        Self {
            version: CURRENT_VERSION,
            suite,
            salt,
            uuid,
            chunk_size,
            argon2_m_cost,
            argon2_t_cost,
            argon2_p_cost,
            flags: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..6].copy_from_slice(MAGIC_BYTES);
        buf[6] = self.version;
        buf[7] = self.suite.as_u8();
        buf[8..40].copy_from_slice(&self.salt);
        buf[40..56].copy_from_slice(&self.uuid);
        buf[56..60].copy_from_slice(&self.chunk_size.to_be_bytes());
        buf[60..64].copy_from_slice(&self.argon2_m_cost.to_be_bytes());
        buf[64..68].copy_from_slice(&self.argon2_t_cost.to_be_bytes());
        buf[68..72].copy_from_slice(&self.argon2_p_cost.to_be_bytes());
        buf[72..76].copy_from_slice(&self.flags.to_be_bytes());
        // 76..80 reserved (0x00)
        buf
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), WraithError> {
        let buf = self.to_bytes();
        writer.write_all(&buf)?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, WraithError> {
        let mut buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                WraithError::UnexpectedEof
            } else {
                WraithError::Io(e)
            }
        })?;

        if &buf[0..6] != MAGIC_BYTES {
            return Err(WraithError::InvalidMagic);
        }

        let version = buf[6];
        if version != CURRENT_VERSION {
            return Err(WraithError::UnsupportedVersion(version));
        }

        let suite = PqcSuite::from_u8(buf[7])?;
        let mut salt = [0u8; 32];
        let mut uuid = [0u8; 16];
        salt.copy_from_slice(&buf[8..40]);
        uuid.copy_from_slice(&buf[40..56]);

        let chunk_size = u32::from_be_bytes(buf[56..60].try_into().unwrap());
        let argon2_m_cost = u32::from_be_bytes(buf[60..64].try_into().unwrap());
        let argon2_t_cost = u32::from_be_bytes(buf[64..68].try_into().unwrap());
        let argon2_p_cost = u32::from_be_bytes(buf[68..72].try_into().unwrap());
        let flags = u32::from_be_bytes(buf[72..76].try_into().unwrap());

        if !(MIN_ARGON2_M_COST..=MAX_ARGON2_M_COST).contains(&argon2_m_cost)
            || !(MIN_ARGON2_T_COST..=MAX_ARGON2_T_COST).contains(&argon2_t_cost)
            || !(MIN_ARGON2_P_COST..=MAX_ARGON2_P_COST).contains(&argon2_p_cost)
        {
            return Err(WraithError::InvalidContainer);
        }

        Ok(Self {
            version,
            suite,
            salt,
            uuid,
            chunk_size,
            argon2_m_cost,
            argon2_t_cost,
            argon2_p_cost,
            flags,
        })
    }
}
