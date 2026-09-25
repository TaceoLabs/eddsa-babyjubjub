use std::{fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer,
    de::{Error as _, SeqAccess, Visitor},
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

    #[test]
    fn bounded_collection_deserializers_reject_oversized_sequences() {
        let oversized =
            serde_json::Value::Array(vec![serde_json::Value::from(1); MAX_PROTOCOL_PARTIES + 1]);

        let Err(_) = deserialize_protocol_vec::<_, u16>(oversized) else {
            panic!("an oversized protocol vector must be rejected");
        };
    }
}
