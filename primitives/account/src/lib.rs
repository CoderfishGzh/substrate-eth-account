//！ 以太坊签名实施
//！ 包括AccountId20的验证和识别特征

#![cfg_attr(not(feature = "std"), no_std)]

use crate::{
	ecdsa::{Public, Signature},
	sp_runtime::traits::{IdentifyAccount, Lazy},
};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
	sp_io, sp_runtime,
	sp_runtime::app_crypto::sp_core::{ecdsa, RuntimeDebug, H160, H256},
};
use scale_info::TypeInfo;
use sha3::{Digest, Keccak256};

/// Account 20 字节的帐号类型，与以太坊帐号类型保持一致
#[derive(
	Eq, PartialOrd, PartialEq, Copy, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Default, Ord,
)]
pub struct AccountId20(pub [u8; 20]);

#[cfg(feature = "std")]
impl std::fmt::Display for AccountId20 {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{:?}", self.0)
	}
}

/// 赋予debug显示功能
impl core::fmt::Debug for AccountId20 {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{:?}", H160(self.0))
	}
}

/// [u8; 20] 转 AccountId20
impl From<[u8; 20]> for AccountId20 {
	fn from(value: [u8; 20]) -> Self {
		Self(value)
	}
}

/// AccountId20 转 [u8; 20]
impl Into<[u8; 20]> for AccountId20 {
	fn into(self) -> [u8; 20] {
		self.0
	}
}

/// H160 转 AccountId20
impl From<H160> for AccountId20 {
	fn from(value: H160) -> Self {
		Self(value.0)
	}
}

/// AccountId20 转 H160
impl Into<H160> for AccountId20 {
	fn into(self) -> H160 {
		H160(self.0)
	}
}

/// 从 str 中 解析出 AccountId20
/// 为了使用 "".parse() 函数
#[cfg(feature = "std")]
impl std::str::FromStr for AccountId20 {
	type Err = &'static str;

	fn from_str(input: &str) -> Result<Self, Self::Err> {
		H160::from_str(input).map(Into::into).map_err(|_| "invalid hex address.")
	}
}

/// 以太坊签名
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Eq, PartialEq, Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct EthereumSignature(ecdsa::Signature);

/// ecdsa Signature 转 EthereumSignature
impl From<ecdsa::Signature> for EthereumSignature {
	fn from(value: Signature) -> Self {
		EthereumSignature(value)
	}
}

/// 为 EthereumSignature 实现substrate 验证功能
impl sp_runtime::traits::Verify for EthereumSignature {
	type Signer = EthereumSigner;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId20) -> bool {
		let mut m = [0u8; 32];
		m.copy_from_slice(Keccak256::digest(msg.get()).as_slice());
		match sp_io::crypto::secp256k1_ecdsa_recover(self.0.as_ref(), &m) {
			Ok(pubkey) =>
				AccountId20(H160::from(H256::from_slice(Keccak256::digest(&pubkey).as_slice())).0) ==
					*signer,
			Err(sp_io::EcdsaVerifyError::BadRS) => {
				log::error!(target: "evm", "Error recovering: Incorrect value of R or S");
				false
			},
			Err(sp_io::EcdsaVerifyError::BadV) => {
				log::error!(target: "evm", "Error recovering: Incorrect value of V");
				false
			},
			Err(sp_io::EcdsaVerifyError::BadSignature) => {
				log::error!(target: "evm", "Error recovering: Invalid signature");
				false
			},
		}
	}
}

/// 以太坊和substrate 兼容的 公钥
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Encode, Decode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct EthereumSigner([u8; 20]);

impl sp_runtime::traits::IdentifyAccount for EthereumSigner {
	type AccountId = AccountId20;

	fn into_account(self) -> Self::AccountId {
		AccountId20(self.0)
	}
}

impl From<[u8; 20]> for EthereumSigner {
	fn from(value: [u8; 20]) -> Self {
		EthereumSigner(value)
	}
}

/// 将 ECDSA 压缩的 公钥 转化成 EthereumSigner
impl From<ecdsa::Public> for EthereumSigner {
	fn from(value: Public) -> Self {
		let decompressed = libsecp256k1::PublicKey::parse_slice(
			&value.0,
			Some(libsecp256k1::PublicKeyFormat::Compressed),
		)
		.expect("Wrong compressed public key provide")
		.serialize();
		let mut m = [0u8; 64];
		m.copy_from_slice(&decompressed[1..65]);
		let account = H160::from(H256::from_slice(Keccak256::digest(&m).as_slice()));
		EthereumSigner(account.into())
	}
}

/// 将从 256k1曲线生成的公钥转换成EthereumSigner
impl From<libsecp256k1::PublicKey> for EthereumSigner {
	fn from(x: libsecp256k1::PublicKey) -> Self {
		let mut m = [0u8; 64];
		m.copy_from_slice(&x.serialize()[1..65]);
		let account = H160::from(H256::from_slice(Keccak256::digest(&m).as_slice()));
		EthereumSigner(account.into())
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for EthereumSigner {
	fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(fmt, "ethereum signature: {:?}", H160::from_slice(&self.0))
	}
}
