//！ 以太坊签名实施
//！ 包括AccountId20的验证和识别特征

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::sp_runtime::app_crypto::sp_core::{H160, ecdsa, RuntimeDebug};
use scale_info::TypeInfo;
use std::fmt::Formatter;
use frame_support::sp_runtime;
use crate::ecdsa::Signature;
use crate::sp_runtime::traits::{IdentifyAccount, Lazy};

/// Account 20 字节的帐号类型，与以太坊帐号类型保持一致
#[derive(
	Eq, PartialOrd, PartialEq, Copy, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Default, Ord,
)]
pub struct AccountId20(pub [u8; 20]);

#[cfg(feature = "std")]
impl std::fmt::Display for AccountId20 {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(f, "{:?}", self.0)
	}
}

/// 赋予debug显示功能
impl core::fmt::Debug for AccountId20 {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
// impl sp_runtime::traits::Verify for EthereumSignature {
// 	type Signer = EthereumSigner;
//
// 	fn verify<L: Lazy<[u8]>>(&self, msg: L, signer: &AccountId20) -> bool {
//
// 	}
// }

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
