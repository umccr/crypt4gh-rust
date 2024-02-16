#[cfg(test)]
mod tests {

	use super::*;

	#[test]
	fn enum_serialization_0() {
		assert_eq!(
			bincode::serialize(&HeaderPacketType::DataEnc).unwrap(),
			0_u32.to_le_bytes()
		);
	}

	#[test]
	fn enum_serialization_1() {
		assert_eq!(
			bincode::serialize(&HeaderPacketType::EditList).unwrap(),
			1_u32.to_le_bytes()
		);
	}
}