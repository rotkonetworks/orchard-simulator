//! Bridge to the real `halo2_proofs` crate.
//!
//! Implements `halo2_proofs::transcript::TranscriptRead<C, Challenge255<C>>`
//! and `TranscriptWrite<C, Challenge255<C>>` for our programmable transcript
//! so the simulator's pre-chosen challenges feed straight into halo2_proofs'
//! verifier path.
//!
//! We specialise on `Challenge255` (halo2's only challenge encoding) so
//! we get `Input = [u8; 64]` and don't fight with generic-bound jungle.
//!
//! Gated behind the `halo2` feature.

#![cfg(feature = "halo2")]

use std::io::{self, Cursor, Read, Write};
use std::marker::PhantomData;

use ff::{FromUniformBytes, PrimeField};
use group::GroupEncoding;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::transcript::{
    Challenge255, EncodedChallenge, Transcript, TranscriptRead, TranscriptWrite,
};

// ---------------------------------------------------------------------------
// Programmable reader transcript (used by the verifier)
// ---------------------------------------------------------------------------

/// halo2-compatible transcript whose `squeeze_challenge` returns
/// pre-programmed values instead of hashing absorbs.
pub struct ProgrammableHalo2Read<R: Read, C: CurveAffine>
where
    C::Scalar: FromUniformBytes<64>,
{
    reader: R,
    challenges: Vec<C::Scalar>,
    cursor: usize,
    _marker: PhantomData<C>,
}

impl<R: Read, C: CurveAffine> ProgrammableHalo2Read<R, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    pub fn new(reader: R, challenges: Vec<C::Scalar>) -> Self {
        Self {
            reader,
            challenges,
            cursor: 0,
            _marker: PhantomData,
        }
    }

    pub fn remaining(&self) -> usize {
        self.challenges.len().saturating_sub(self.cursor)
    }
}

impl<R: Read, C: CurveAffine> Transcript<C, Challenge255<C>> for ProgrammableHalo2Read<R, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        let s = self
            .challenges
            .get(self.cursor)
            .copied()
            .expect("ProgrammableHalo2Read ran out of pre-programmed challenges");
        self.cursor += 1;
        Challenge255::<C>::new(&scalar_to_64_bytes::<C>(s))
    }

    fn common_point(&mut self, _point: C) -> io::Result<()> {
        Ok(())
    }
    fn common_scalar(&mut self, _scalar: C::Scalar) -> io::Result<()> {
        Ok(())
    }
}

impl<R: Read, C: CurveAffine> TranscriptRead<C, Challenge255<C>> for ProgrammableHalo2Read<R, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn read_point(&mut self) -> io::Result<C> {
        let mut buf = <C as GroupEncoding>::Repr::default();
        self.reader.read_exact(buf.as_mut())?;
        Option::<C>::from(C::from_bytes(&buf))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid curve point"))
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        let mut buf = <C::Scalar as PrimeField>::Repr::default();
        self.reader.read_exact(buf.as_mut())?;
        // The byte buffer is not secret here (it's already on the wire),
        // but the recovered scalar will be; caller should `zeroize` it
        // through the wrapping `Zeroizing<>` API when appropriate.
        Option::<C::Scalar>::from(C::Scalar::from_repr(buf))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid scalar"))
    }
}

// ---------------------------------------------------------------------------
// Programmable writer transcript (used by the simulator to emit proof bytes)
// ---------------------------------------------------------------------------

pub struct ProgrammableHalo2Write<W: Write, C: CurveAffine>
where
    C::Scalar: FromUniformBytes<64>,
{
    writer: W,
    challenges: Vec<C::Scalar>,
    cursor: usize,
    _marker: PhantomData<C>,
}

impl<W: Write, C: CurveAffine> ProgrammableHalo2Write<W, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    pub fn new(writer: W, challenges: Vec<C::Scalar>) -> Self {
        Self {
            writer,
            challenges,
            cursor: 0,
            _marker: PhantomData,
        }
    }

    pub fn finalize(self) -> W {
        self.writer
    }

    pub fn remaining(&self) -> usize {
        self.challenges.len().saturating_sub(self.cursor)
    }
}

impl<W: Write, C: CurveAffine> Transcript<C, Challenge255<C>> for ProgrammableHalo2Write<W, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        let s = self
            .challenges
            .get(self.cursor)
            .copied()
            .expect("ProgrammableHalo2Write ran out of pre-programmed challenges");
        self.cursor += 1;
        Challenge255::<C>::new(&scalar_to_64_bytes::<C>(s))
    }

    fn common_point(&mut self, _point: C) -> io::Result<()> {
        Ok(())
    }
    fn common_scalar(&mut self, _scalar: C::Scalar) -> io::Result<()> {
        Ok(())
    }
}

impl<W: Write, C: CurveAffine> TranscriptWrite<C, Challenge255<C>> for ProgrammableHalo2Write<W, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn write_point(&mut self, point: C) -> io::Result<()> {
        let bytes = <C as GroupEncoding>::to_bytes(&point);
        self.writer.write_all(bytes.as_ref())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        // No-secret-leak here: the scalar's repr lives only on this stack
        // frame and is moved into the writer. Witness/blinder secrets that
        // *do* live in long-lived state are zeroized at their definition
        // site, not here.
        let bytes = scalar.to_repr();
        self.writer.write_all(bytes.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Counting transcript (diagnostic)
// ---------------------------------------------------------------------------

/// Wraps a `TranscriptWrite` and records how many `write_point`,
/// `write_scalar`, and `squeeze_challenge` calls it sees, plus the order of
/// operations. Used to derive the exact byte structure of a halo2_proofs
/// proof for a given circuit, so the no-witness simulator can emit a
/// matching sequence.
pub struct CountingTranscript<Inner, C: CurveAffine>
where
    C::Scalar: FromUniformBytes<64>,
{
    pub inner: Inner,
    pub ops: Vec<TranscriptOp>,
    _marker: PhantomData<C>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TranscriptOp {
    WritePoint,
    WriteScalar,
    Squeeze,
    CommonPoint,
    CommonScalar,
}

impl<Inner, C: CurveAffine> CountingTranscript<Inner, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    pub fn new(inner: Inner) -> Self {
        Self {
            inner,
            ops: Vec::new(),
            _marker: PhantomData,
        }
    }

    pub fn op_summary(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let mut last_op: Option<&TranscriptOp> = None;
        let mut run = 0u32;
        for op in &self.ops {
            if Some(op) == last_op {
                run += 1;
            } else {
                if let Some(prev) = last_op {
                    let _ = write!(s, "{prev:?}×{run} ");
                }
                last_op = Some(op);
                run = 1;
            }
        }
        if let Some(prev) = last_op {
            let _ = write!(s, "{prev:?}×{run}");
        }
        s
    }
}

impl<Inner, C: CurveAffine> Transcript<C, Challenge255<C>> for CountingTranscript<Inner, C>
where
    Inner: Transcript<C, Challenge255<C>>,
    C::Scalar: FromUniformBytes<64>,
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        self.ops.push(TranscriptOp::Squeeze);
        self.inner.squeeze_challenge()
    }

    fn common_point(&mut self, p: C) -> io::Result<()> {
        self.ops.push(TranscriptOp::CommonPoint);
        self.inner.common_point(p)
    }

    fn common_scalar(&mut self, s: C::Scalar) -> io::Result<()> {
        self.ops.push(TranscriptOp::CommonScalar);
        self.inner.common_scalar(s)
    }
}

impl<Inner, C: CurveAffine> TranscriptWrite<C, Challenge255<C>> for CountingTranscript<Inner, C>
where
    Inner: TranscriptWrite<C, Challenge255<C>>,
    C::Scalar: FromUniformBytes<64>,
{
    fn write_point(&mut self, p: C) -> io::Result<()> {
        self.ops.push(TranscriptOp::WritePoint);
        self.inner.write_point(p)
    }

    fn write_scalar(&mut self, s: C::Scalar) -> io::Result<()> {
        self.ops.push(TranscriptOp::WriteScalar);
        self.inner.write_scalar(s)
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Build a `[u8; 64]` `Challenge255::Input` from a scalar by right-padding
/// the scalar's `to_repr` bytes. The reduction via `from_uniform_bytes` then
/// recovers the original scalar (assuming scalar bit-length ≤ 256).
fn scalar_to_64_bytes<C: CurveAffine>(scalar: C::Scalar) -> [u8; 64] {
    let repr = scalar.to_repr();
    let bytes = repr.as_ref();
    let mut input = [0u8; 64];
    let n = input.len().min(bytes.len());
    input[..n].copy_from_slice(&bytes[..n]);
    input
}

// ---------------------------------------------------------------------------
// In-memory paired writer/reader for tests
// ---------------------------------------------------------------------------

// `impl Trait` is not stable in type aliases (RFC 2515 still gated), so
// the return tuple has to be spelled in line. The complexity is the
// shape of the API, not accidental.
#[allow(clippy::type_complexity)]
pub fn paired_writer_reader<C: CurveAffine>(
    challenges: Vec<C::Scalar>,
) -> (
    ProgrammableHalo2Write<Cursor<Vec<u8>>, C>,
    impl FnOnce(Vec<u8>) -> ProgrammableHalo2Read<Cursor<Vec<u8>>, C>,
)
where
    C::Scalar: FromUniformBytes<64>,
{
    let writer = ProgrammableHalo2Write::new(Cursor::new(Vec::new()), challenges.clone());
    let reader_factory =
        move |bytes: Vec<u8>| ProgrammableHalo2Read::new(Cursor::new(bytes), challenges);
    (writer, reader_factory)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use group::{Curve, Group};
    use halo2_proofs::pasta::{Ep, EpAffine};
    use rand::SeedableRng;

    type C = EpAffine;

    #[test]
    fn programmable_transcript_round_trips_points_and_scalars() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x10);

        let prog: Vec<<C as CurveAffine>::ScalarExt> = (0..4)
            .map(|_| <C as CurveAffine>::ScalarExt::random(&mut rng))
            .collect();

        let p0: C = Ep::random(&mut rng).to_affine();
        let s0 = <C as CurveAffine>::ScalarExt::random(&mut rng);

        let mut writer = ProgrammableHalo2Write::<_, C>::new(Cursor::new(Vec::new()), prog.clone());
        writer.write_point(p0).unwrap();
        writer.write_scalar(s0).unwrap();
        let c0 = writer.squeeze_challenge();
        let c1 = writer.squeeze_challenge();
        let bytes = writer.finalize().into_inner();

        let mut reader = ProgrammableHalo2Read::<_, C>::new(Cursor::new(bytes), prog);
        let p1 = reader.read_point().unwrap();
        let s1 = reader.read_scalar().unwrap();
        let c2 = reader.squeeze_challenge();
        let c3 = reader.squeeze_challenge();

        assert_eq!(p0, p1);
        assert_eq!(s0, s1);
        assert_eq!(*c0.as_ref(), *c2.as_ref());
        assert_eq!(*c1.as_ref(), *c3.as_ref());
    }
}
