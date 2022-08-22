/******************************************************************************
 *
 *  Copyright 2022 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/******************************************************************************
 *                                 IMPORTANT
 *
 * These cryptography methods do not provide any security or correctness
 * ensurance.
 * They should be used only in Bluetooth emulation, not including any production
 * environment.
 *
 ******************************************************************************/

use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use rand::{thread_rng, Rng};
use std::convert::TryInto;
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    P192([u8; P192r1::PUBLIC_KEY_SIZE]),
    P256([u8; P256r1::PUBLIC_KEY_SIZE]),
}

impl PublicKey {
    pub fn new(size: usize) -> Option<Self> {
        match size {
            P192r1::PUBLIC_KEY_SIZE => Some(Self::P192([0; P192r1::PUBLIC_KEY_SIZE])),
            P256r1::PUBLIC_KEY_SIZE => Some(Self::P256([0; P256r1::PUBLIC_KEY_SIZE])),
            _ => None,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if let Ok(inner) = bytes.try_into() {
            Some(PublicKey::P192(inner))
        } else if let Ok(inner) = bytes.try_into() {
            Some(PublicKey::P256(inner))
        } else {
            None
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            PublicKey::P192(inner) => inner,
            PublicKey::P256(inner) => inner,
        }
    }

    pub fn size(&self) -> usize {
        self.as_slice().len()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            PublicKey::P192(inner) => inner,
            PublicKey::P256(inner) => inner,
        }
    }

    fn get_x(&self) -> BigInt {
        BigInt::from_signed_bytes_le(&self.as_slice()[0..self.size() / 2])
    }

    fn get_y(&self) -> BigInt {
        BigInt::from_signed_bytes_le(&self.as_slice()[self.size() / 2..self.size()])
    }

    fn to_point<Curve: EllipticCurve>(&self) -> Point<Curve> {
        Point::new(&self.get_x(), &self.get_y())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateKey {
    P192([u8; P192r1::PRIVATE_KEY_SIZE]),
    P256([u8; P256r1::PRIVATE_KEY_SIZE]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhKey {
    P192([u8; P192r1::PUBLIC_KEY_SIZE]),
    P256([u8; P256r1::PUBLIC_KEY_SIZE]),
}

impl DhKey {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if let Ok(inner) = bytes.try_into() {
            Some(DhKey::P192(inner))
        } else if let Ok(inner) = bytes.try_into() {
            Some(DhKey::P256(inner))
        } else {
            None
        }
    }
}

impl PrivateKey {
    // Generate a private key in range[1,2**191]
    pub fn generate_p192() -> Self {
        let random_bytes: [u8; P192r1::PRIVATE_KEY_SIZE] = thread_rng().gen();
        let mut key = BigInt::from_signed_bytes_le(&random_bytes);

        if key.is_negative() {
            key = -key;
        }
        if key < BigInt::one() {
            key = BigInt::one();
        }
        let buf = key.to_signed_bytes_le();
        let mut inner = [0; P192r1::PRIVATE_KEY_SIZE];
        inner[0..buf.len()].copy_from_slice(&buf);
        Self::P192(inner)
    }

    pub fn generate_p256() -> Self {
        let random_bytes: [u8; P256r1::PRIVATE_KEY_SIZE] = thread_rng().gen();
        let mut key = BigInt::from_signed_bytes_le(&random_bytes);

        if key.is_negative() {
            key = -key;
        }
        if key < BigInt::one() {
            key = BigInt::one();
        }
        let buf = key.to_signed_bytes_le();
        let mut inner = [0; P256r1::PRIVATE_KEY_SIZE];
        inner[0..buf.len()].copy_from_slice(&buf);
        Self::P256(inner)
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            PrivateKey::P192(inner) => inner,
            PrivateKey::P256(inner) => inner,
        }
    }

    fn to_bigint(&self) -> BigInt {
        BigInt::from_signed_bytes_le(self.as_slice())
    }

    pub fn derive(&self) -> PublicKey {
        let bytes = match self {
            PrivateKey::P192(_) => {
                Point::<P192r1>::generate_public_key(&self.to_bigint()).to_bytes()
            }
            PrivateKey::P256(_) => {
                Point::<P256r1>::generate_public_key(&self.to_bigint()).to_bytes()
            }
        }
        .unwrap();
        PublicKey::from_bytes(&bytes).unwrap()
    }

    pub fn shared_secret(&self, peer_public_key: PublicKey) -> DhKey {
        let bytes = match self {
            PrivateKey::P192(_) => {
                (&peer_public_key.to_point::<P192r1>() * &self.to_bigint()).to_bytes()
            }
            PrivateKey::P256(_) => {
                (&peer_public_key.to_point::<P256r1>() * &self.to_bigint()).to_bytes()
            }
        }
        .unwrap();
        DhKey::from_bytes(&bytes).unwrap()
    }
}

// Modular Inverse
fn mod_inv(x: &BigInt, m: &BigInt) -> Option<BigInt> {
    let egcd = x.extended_gcd(m);
    if !egcd.gcd.is_one() {
        None
    } else {
        Some(egcd.x % m)
    }
}

trait EllipticCurve {
    type Param: AsRef<[u8]>;
    const A: i32;
    const P: Self::Param;
    const G_X: Self::Param;
    const G_Y: Self::Param;
    const PRIVATE_KEY_SIZE: usize;
    const PUBLIC_KEY_SIZE: usize;

    fn p() -> BigInt {
        BigInt::from_bytes_be(Sign::Plus, Self::P.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq)]
struct P192r1;

impl EllipticCurve for P192r1 {
    type Param = [u8; 24];

    const A: i32 = -3;
    const P: Self::Param = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    const G_X: Self::Param = [
        0x18, 0x8d, 0xa8, 0x0e, 0xb0, 0x30, 0x90, 0xf6, 0x7c, 0xbf, 0x20, 0xeb, 0x43, 0xa1, 0x88,
        0x00, 0xf4, 0xff, 0x0a, 0xfd, 0x82, 0xff, 0x10, 0x12,
    ];
    const G_Y: Self::Param = [
        0x07, 0x19, 0x2b, 0x95, 0xff, 0xc8, 0xda, 0x78, 0x63, 0x10, 0x11, 0xed, 0x6b, 0x24, 0xcd,
        0xd5, 0x73, 0xf9, 0x77, 0xa1, 0x1e, 0x79, 0x48, 0x11,
    ];
    const PRIVATE_KEY_SIZE: usize = 24;
    const PUBLIC_KEY_SIZE: usize = 48;
}

#[derive(Debug, Clone, PartialEq)]
struct P256r1;

impl EllipticCurve for P256r1 {
    type Param = [u8; 32];

    const A: i32 = -3;
    const P: Self::Param = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];
    const G_X: Self::Param = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];
    const G_Y: Self::Param = [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];
    const PRIVATE_KEY_SIZE: usize = 32;
    const PUBLIC_KEY_SIZE: usize = 64;
}

#[derive(Debug, PartialEq)]
enum Point<Curve> {
    Infinite(PhantomData<Curve>),
    Finite { x: BigInt, y: BigInt, _curve: PhantomData<Curve> },
}

impl<Curve> Point<Curve>
where
    Curve: EllipticCurve,
{
    fn o() -> Self {
        Point::Infinite(PhantomData)
    }

    fn generate_public_key(private_key: &BigInt) -> Self {
        &Self::g() * private_key
    }

    fn new(x: &BigInt, y: &BigInt) -> Self {
        Point::Finite { x: x.clone(), y: y.clone(), _curve: PhantomData }
    }

    fn g() -> Self {
        Self::new(
            &BigInt::from_bytes_be(Sign::Plus, Curve::G_X.as_ref()),
            &BigInt::from_bytes_be(Sign::Plus, Curve::G_Y.as_ref()),
        )
    }

    #[cfg(test)]
    fn get_x(&self) -> Option<BigInt> {
        match self {
            Point::Infinite(_) => None,
            Point::Finite { x, .. } => Some(x.clone()),
        }
    }

    fn to_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Point::Infinite(_) => None,
            Point::Finite { x, y, _curve: _ } => {
                let mut x = x.to_signed_bytes_le();
                x.resize(Curve::PRIVATE_KEY_SIZE, 0);
                let mut y = y.to_signed_bytes_le();
                y.resize(Curve::PRIVATE_KEY_SIZE, 0);
                x.append(&mut y);
                Some(x)
            }
        }
    }
}

impl<Curve> Clone for Point<Curve>
where
    Curve: EllipticCurve,
{
    fn clone(&self) -> Self {
        match self {
            Point::Infinite(_) => Point::o(),
            Point::Finite { x, y, .. } => Point::new(x, y),
        }
    }
}

// Elliptic Curve Group Addition
// https://mathworld.wolfram.com/EllipticCurve.html
impl<Curve> std::ops::Add<&Point<Curve>> for &Point<Curve>
where
    Curve: EllipticCurve,
{
    type Output = Point<Curve>;

    fn add(self, rhs: &Point<Curve>) -> Self::Output {
        // P + O = O + P = P
        match (self, rhs) {
            (Point::Infinite(_), Point::Infinite(_)) => Self::Output::o(),
            (Point::Infinite(_), Point::Finite { .. }) => rhs.clone(),
            (Point::Finite { .. }, Point::Infinite(_)) => self.clone(),
            (
                Point::Finite { _curve: _, x: x1, y: y1 },
                Point::Finite { _curve: _, x: x2, y: y2 },
            ) => {
                // P + (-P) = O
                if x1 == x2 && y1 == &(-y2) {
                    return Self::Output::o();
                }
                let p = &Curve::p();
                // d(x^3 + ax + b) / dx = (3x^2 + a) / 2y
                let slope = if x1 == x2 {
                    (&(3 * x1.pow(2) + Curve::A) * &mod_inv(&(2 * y1), p).unwrap()) % p
                } else {
                    // dy/dx = (y2 - y1) / (x2 - x1)
                    (&(y2 - y1) * &mod_inv(&(x2 - x1), p).unwrap()) % p
                };
                // Solving (x-p)(x-q)(x-r) = x^3 + ax + b
                // => x = d^2 - x1 - x2
                let x = (slope.pow(2) - x1 - x2) % p;
                let y = (slope * (x1 - &x) - y1) % p;
                Point::new(&x, &y)
            }
        }
    }
}

impl<Curve> std::ops::Mul<&BigInt> for &Point<Curve>
where
    Curve: EllipticCurve,
{
    type Output = Point<Curve>;

    fn mul(self, rhs: &BigInt) -> Self::Output {
        let mut addend = self.clone();
        let mut result = Point::o();
        let mut i = rhs.clone();

        // O(logN) double-and-add multiplication
        while !i.is_zero() {
            if i.is_odd() {
                result = &result + &addend;
            }
            addend = &addend + &addend;
            i /= 2;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::ec::*;
    use num_bigint::BigInt;

    struct EcTestCase<const N: usize> {
        pub priv_a: [u8; N],
        pub priv_b: [u8; N],
        pub pub_a: [u8; N],
        pub dh_x: [u8; N],
    }

    // Private A, Private B, Public A(x), DHKey
    const P192_TEST_CASES: [EcTestCase<48>; 4] = [
        EcTestCase::<48> {
            priv_a: *b"07915f86918ddc27005df1d6cf0c142b625ed2eff4a518ff",
            priv_b: *b"1e636ca790b50f68f15d8dbe86244e309211d635de00e16d",
            pub_a: *b"15207009984421a6586f9fc3fe7e4329d2809ea51125f8ed",
            dh_x: *b"fb3ba2012c7e62466e486e229290175b4afebc13fdccee46",
        },
        EcTestCase::<48> {
            priv_a: *b"52ec1ca6e0ec973c29065c3ca10be80057243002f09bb43e",
            priv_b: *b"57231203533e9efe18cc622fd0e34c6a29c6e0fa3ab3bc53",
            pub_a: *b"45571f027e0d690795d61560804da5de789a48f94ab4b07e",
            dh_x: *b"a20a34b5497332aa7a76ab135cc0c168333be309d463c0c0",
        },
        EcTestCase::<48> {
            priv_a: *b"00a0df08eaf51e6e7be519d67c6749ea3f4517cdd2e9e821",
            priv_b: *b"2bf5e0d1699d50ca5025e8e2d9b13244b4d322a328be1821",
            pub_a: *b"2ed35b430fa45f9d329186d754eeeb0495f0f653127f613d",
            dh_x: *b"3b3986ba70790762f282a12a6d3bcae7a2ca01e25b87724e",
        },
        EcTestCase::<48> {
            priv_a: *b"030a4af66e1a4d590a83e0284fca5cdf83292b84f4c71168",
            priv_b: *b"12448b5c69ecd10c0471060f2bf86345c5e83c03d16bae2c",
            pub_a: *b"f24a6899218fa912e7e4a8ba9357cb8182958f9fa42c968c",
            dh_x: *b"4a78f83fba757c35f94abea43e92effdd2bc700723c61939",
        },
    ];

    // Private A, Private B, Public A(x), DHKey
    const P256_TEST_CASES: [EcTestCase<64>; 2] = [
        EcTestCase::<64> {
            priv_a: *b"3f49f6d4a3c55f3874c9b3e3d2103f504aff607beb40b7995899b8a6cd3c1abd",
            priv_b: *b"55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd",
            pub_a: *b"20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6",
            dh_x: *b"ec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698",
        },
        EcTestCase::<64> {
            priv_a: *b"06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663",
            priv_b: *b"529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba",
            pub_a: *b"2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd",
            dh_x: *b"ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69",
        },
    ];

    #[test]
    fn p192() {
        for test_case in P192_TEST_CASES {
            let priv_a = BigInt::parse_bytes(&test_case.priv_a, 16).unwrap();
            let priv_b = BigInt::parse_bytes(&test_case.priv_b, 16).unwrap();
            let pub_a = Point::<P192r1>::generate_public_key(&priv_a);
            let pub_b = Point::<P192r1>::generate_public_key(&priv_b);
            assert_eq!(pub_a.get_x().unwrap(), BigInt::parse_bytes(&test_case.pub_a, 16).unwrap());
            let shared = &pub_a * &priv_b;
            assert_eq!(shared.get_x().unwrap(), BigInt::parse_bytes(&test_case.dh_x, 16).unwrap());
            assert_eq!((&pub_a * &priv_b).get_x().unwrap(), (&pub_b * &priv_a).get_x().unwrap());
        }
    }

    #[test]
    fn p256() {
        for test_case in P256_TEST_CASES {
            let priv_a = BigInt::parse_bytes(&test_case.priv_a, 16).unwrap();
            let priv_b = BigInt::parse_bytes(&test_case.priv_b, 16).unwrap();
            let pub_a = Point::<P256r1>::generate_public_key(&priv_a);
            let pub_b = Point::<P256r1>::generate_public_key(&priv_b);
            assert_eq!(pub_a.get_x().unwrap(), BigInt::parse_bytes(&test_case.pub_a, 16).unwrap());
            let shared = &pub_a * &priv_b;
            assert_eq!(shared.get_x().unwrap(), BigInt::parse_bytes(&test_case.dh_x, 16).unwrap());
            assert_eq!((&pub_a * &priv_b).get_x().unwrap(), (&pub_b * &priv_a).get_x().unwrap());
        }
    }
}
