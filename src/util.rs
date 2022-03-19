
pub trait DataContainer {
    fn data(&self) -> &[u8];
}

#[inline]
pub fn tou16(data: &[u8]) -> u16 {
    (data[0] as u16) << 8 | (data[1] as u16)
}

#[inline]
pub fn tou32(data: &[u8]) -> u32 {
    (tou16(&data[0..2]) as u32) << 16 | (tou16(&data[2..4]) as u32)
}

#[inline]
pub fn tou64(data: &[u8]) -> u64 {
    (tou32(&data[0..4]) as u64) << 32 | (tou32(&data[4..8]) as u64)
}

#[inline]
pub fn tou128(data: &[u8]) -> u128 {
    (tou64(&data[0..8]) as u128) << 64 | (tou64(&data[8..16]) as u128)
}
