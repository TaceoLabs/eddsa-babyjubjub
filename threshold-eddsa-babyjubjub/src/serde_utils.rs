use std::{collections::BTreeSet, fmt, marker::PhantomData};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, CompressedChecked};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
    ser::{Error as _, SerializeSeq},
};

/// Party identifiers and protocol thresholds are represented as `u16` values,
/// so no honest participant-sized collection can exceed this limit.
///
/// This is a generic ceiling, not a tight bound: the exact expected length is usually
/// `Parameters::threshold`, but that is not visible to a Serde adapter. A maximally sized
/// commitment vector therefore still costs one subgroup check per element before the caller's own
/// length check runs. Reject oversized frames at the transport, as the crate README requires.
///
/// Note also that these adapters encode a sequence with per-element framing rather than one
/// `ark-serialize` blob, so the wire format differs from a plain `CompressedChecked<Vec<_>>`.
pub(crate) const MAX_PROTOCOL_PARTIES: usize = u16::MAX as usize;

pub(crate) fn serialize_protocol_vec<S, T>(values: &[T], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    if values.len() > MAX_PROTOCOL_PARTIES {
        return Err(S::Error::custom("protocol collection exceeds u16 limit"));
    }

    let mut sequence = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        sequence.serialize_element(value)?;
    }
    sequence.end()
}

pub(crate) fn deserialize_protocol_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor(PhantomData))
}

struct BoundedVecVisitor<T>(PhantomData<fn() -> T>);

impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a sequence containing at most {MAX_PROTOCOL_PARTIES} elements"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        reject_oversized_hint(sequence.size_hint(), &self)?;

        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            if values.len() == MAX_PROTOCOL_PARTIES {
                return Err(A::Error::invalid_length(MAX_PROTOCOL_PARTIES + 1, &self));
            }
            values.push(value);
        }
        Ok(values)
    }
}

pub(crate) fn deserialize_protocol_btree_set<'de, D, T>(
    deserializer: D,
) -> Result<BTreeSet<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Ord,
{
    deserializer.deserialize_seq(BoundedSetVisitor(PhantomData))
}

struct BoundedSetVisitor<T>(PhantomData<fn() -> T>);

impl<'de, T> Visitor<'de> for BoundedSetVisitor<T>
where
    T: Deserialize<'de> + Ord,
{
    type Value = BTreeSet<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a set containing at most {MAX_PROTOCOL_PARTIES} elements"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        reject_oversized_hint(sequence.size_hint(), &self)?;

        let mut values = BTreeSet::new();
        let mut received = 0;
        while let Some(value) = sequence.next_element()? {
            if received == MAX_PROTOCOL_PARTIES {
                return Err(A::Error::invalid_length(MAX_PROTOCOL_PARTIES + 1, &self));
            }
            received += 1;
            values.insert(value);
        }
        Ok(values)
    }
}

pub(crate) fn serialize_canonical_protocol_vec<S, T>(
    values: &[T],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: CanonicalSerialize,
{
    if values.len() > MAX_PROTOCOL_PARTIES {
        return Err(S::Error::custom("protocol collection exceeds u16 limit"));
    }

    let mut sequence = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        sequence.serialize_element(&CompressedChecked(value))?;
    }
    sequence.end()
}

pub(crate) fn deserialize_canonical_protocol_vec<'de, D, T>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: CanonicalDeserialize,
{
    deserializer.deserialize_seq(CanonicalVisitor(PhantomData))
}

struct CanonicalVisitor<T>(PhantomData<fn() -> T>);

impl<'de, T> Visitor<'de> for CanonicalVisitor<T>
where
    T: CanonicalDeserialize,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a sequence containing at most {MAX_PROTOCOL_PARTIES} canonical elements"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        reject_oversized_hint(sequence.size_hint(), &self)?;

        let mut values = Vec::new();
        while let Some(CompressedChecked(value)) = sequence.next_element()? {
            if values.len() == MAX_PROTOCOL_PARTIES {
                return Err(A::Error::invalid_length(MAX_PROTOCOL_PARTIES + 1, &self));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn reject_oversized_hint<E: serde::de::Error>(
    size_hint: Option<usize>,
    expected: &dyn serde::de::Expected,
) -> Result<(), E> {
    if size_hint.is_some_and(|length| length > MAX_PROTOCOL_PARTIES) {
        return Err(E::invalid_length(MAX_PROTOCOL_PARTIES + 1, expected));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScalarField;

    #[test]
    fn bounded_collection_deserializers_reject_oversized_sequences() {
        let oversized =
            serde_json::Value::Array(vec![serde_json::Value::from(1); MAX_PROTOCOL_PARTIES + 1]);

        let Err(_) = deserialize_protocol_vec::<_, u16>(oversized.clone()) else {
            panic!("an oversized protocol vector must be rejected");
        };
        let Err(_) = deserialize_protocol_btree_set::<_, u16>(oversized.clone()) else {
            panic!("an oversized protocol set must be rejected");
        };
        let Err(_) = deserialize_canonical_protocol_vec::<_, ScalarField>(oversized) else {
            panic!("an oversized canonical protocol vector must be rejected");
        };
    }
}
