use crate::sys::{MemoryDump, MemoryDumpRegion};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while_m_n},
    character::complete::multispace0,
    combinator::{map, map_res},
    error::Error,
    multi::many0,
    sequence::preceded,
    Err, IResult,
};
use std::str::FromStr;

type ParseError<T> = Err<Error<T>>;

#[derive(Debug, Clone)]
pub enum SignatureUnit {
    KnownByte(u8),
    UnknownByte,
}

impl PartialEq<SignatureUnit> for SignatureUnit {
    fn eq(&self, other: &SignatureUnit) -> bool {
        match self {
            Self::KnownByte(b1) => match other {
                Self::KnownByte(b2) => b1 == b2,
                _ => false,
            },
            Self::UnknownByte => match other {
                Self::UnknownByte => true,
                _ => false,
            },
        }
    }
}

impl PartialEq<u8> for SignatureUnit {
    fn eq(&self, other: &u8) -> bool {
        match self {
            Self::KnownByte(b) => b.eq(other),
            Self::UnknownByte => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Signature(Vec<SignatureUnit>);

fn parse_signature(s: &str) -> IResult<&str, Signature> {
    map(
        many0(preceded(
            multispace0,
            alt((
                map(tag("??"), |_| SignatureUnit::UnknownByte),
                map_res(
                    take_while_m_n(2, 2, |c: char| c.is_ascii_hexdigit()),
                    |hexit| {
                        u8::from_str_radix(hexit, 16).map(|byte| SignatureUnit::KnownByte(byte))
                    },
                ),
            )),
        )),
        |units| units.into(),
    )(s)
}

impl FromStr for Signature {
    type Err = ParseError<String>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, sig) = parse_signature(s).map_err(|e| e.to_owned())?;
        Ok(sig)
    }
}

pub struct BytesSignatureMatch<'a> {
    offset: usize,
    data: &'a [u8],
}

impl<'a> BytesSignatureMatch<'a> {
    pub fn offset(&self) -> usize {
        self.offset
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

pub struct RegionSignatureMatch<'a> {
    region: &'a MemoryDumpRegion,
    addr: usize,
    data: &'a [u8],
}

impl<'a> RegionSignatureMatch<'a> {
    pub fn region(&self) -> &MemoryDumpRegion {
        &self.region
    }
    pub fn addr(&self) -> usize {
        self.addr
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Signature {
    pub fn scan_bytes<'a>(&self, bytes: &'a [u8]) -> Vec<BytesSignatureMatch<'a>> {
        let mut matches = Vec::new();
        let mut offset = 0;
        'window: for window in bytes.windows(self.len()) {
            for (unit, byte) in self.0.iter().zip(window.iter()) {
                if unit != byte {
                    offset += 1;
                    continue 'window;
                }
            }
            matches.push(BytesSignatureMatch {
                offset,
                data: &bytes[offset..offset + self.len()],
            });
            offset += 1;
        }
        matches
    }

    pub fn match_bytes(&self, bytes: &[u8]) -> bool {
        'window: for window in bytes.windows(self.len()) {
            for (unit, byte) in self.0.iter().zip(window.iter()) {
                if unit != byte {
                    continue 'window;
                }
            }
            return true;
        }
        false
    }

    pub fn scan_region<'a>(&self, region: &'a MemoryDumpRegion) -> Vec<RegionSignatureMatch<'a>> {
        let bytes = region.data();
        let mut matches = Vec::new();
        let mut offset = 0;
        'window: for window in bytes.windows(self.len()) {
            for (unit, byte) in self.0.iter().zip(window.iter()) {
                if unit != byte {
                    offset += 1;
                    continue 'window;
                }
            }
            matches.push(RegionSignatureMatch {
                region: region,
                addr: region.addr_min() + offset,
                data: &bytes[offset..offset + self.len()],
            });
            offset += 1;
        }
        matches
    }

    pub fn scan_dump<'a>(
        &self,
        dump: &'a MemoryDump,
        start_region_addr: Option<usize>,
    ) -> Vec<RegionSignatureMatch<'a>> {
        let mut matches = Vec::new();
        if let Some(start_region_addr) = start_region_addr {
            for region in dump
                .regions()
                .iter()
                .filter(|region| region.addr_min() >= start_region_addr)
            {
                matches.append(self.scan_region(region).as_mut());
            }
        } else {
            for region in dump.regions().iter() {
                matches.append(self.scan_region(region).as_mut());
            }
        }
        matches
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<SignatureUnit>> for Signature {
    fn from(value: Vec<SignatureUnit>) -> Self {
        Self(value)
    }
}
