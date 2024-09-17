use core::ops::{Index, Range, RangeFrom, RangeInclusive, RangeTo};
use std::cmp;

use crate::layers::dev_traits::LayerName;
use crate::prelude::*;

pub struct PacketWriter<'a, T: PacketWritable> {
    writable: &'a mut T,
    error_layer: &'static str, // TODO: remove?
}

impl<'a, T: PacketWritable> PacketWriter<'a, T> {
    /// Constructs a new writer with errors reported as originating from layer `L`.
    #[inline]
    pub fn new<L: LayerName>(writable: &'a mut T) -> Self {
        Self {
            writable,
            error_layer: L::name(),
        }
    }

    /// Constructs a new writer with errors reported as originating from `layer_naem`.
    #[inline]
    pub(crate) fn new_with_layer(writable: &'a mut T, layer_name: &'static str) -> Self {
        Self {
            writable,
            error_layer: layer_name,
        }
    }

    /// Updates the `Layer` that errors will be reported as originating from.
    #[inline]
    pub fn update_layer<L: LayerName>(&mut self) {
        self.error_layer = L::name();
    }

    /// Writes the data to the writer at its current index.
    #[inline]
    pub fn write_slice(&mut self, data: &[u8]) -> Result<(), SerializationError> {
        self.writable.write_slice(data).map_err(|e| match e {
            IndexedWriteError::OutOfRange => SerializationError::internal(self.error_layer),
            IndexedWriteError::InsufficientBytes => {
                SerializationError::insufficient_buffer(self.error_layer)
            }
        })
    }

    /// Writes data to the specified index position.
    ///
    /// This method will panic if `pos` is greater than the current written length of the buffer.
    #[inline]
    pub fn write_slice_at(&mut self, data: &[u8], pos: usize) -> Result<(), SerializationError> {
        self.writable
            .write_slice_at(data, pos)
            .map_err(|e| match e {
                IndexedWriteError::OutOfRange => SerializationError::internal(self.error_layer),
                IndexedWriteError::InsufficientBytes => {
                    SerializationError::insufficient_buffer(self.error_layer)
                }
            })
    }

    /// Returns the current length of bytes written to the writer.
    ///
    /// Note that this is NOT the amount of available space the writer has left to write to.
    #[inline]
    pub fn len(&self) -> usize {
        self.writable.len()
    }

    /// Shifts the writer's index back to the provided index position, truncating the stream.
    ///
    /// This method will return an error if `pos` is greater than the current written length of the
    /// buffer.
    #[inline]
    pub fn truncate(&mut self, num_bytes: usize) -> Result<(), SerializationError> {
        self.writable.truncate(num_bytes).map_err(|e| match e {
            IndexedWriteError::OutOfRange => SerializationError::internal(self.error_layer),
            IndexedWriteError::InsufficientBytes => {
                SerializationError::insufficient_buffer(self.error_layer)
            }
        })
    }
}

impl<T: PacketWritable> Index<usize> for PacketWriter<'_, T> {
    type Output = <T as Index<usize>>::Output;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.writable.index(index)
    }
}

impl<T: PacketWritable> Index<Range<usize>> for PacketWriter<'_, T> {
    type Output = <T as Index<Range<usize>>>::Output;

    #[inline]
    fn index(&self, index: Range<usize>) -> &Self::Output {
        self.writable.index(index)
    }
}

impl<T: PacketWritable> Index<RangeFrom<usize>> for PacketWriter<'_, T> {
    type Output = <T as Index<RangeFrom<usize>>>::Output;

    #[inline]
    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        self.writable.index(index)
    }
}

impl<T: PacketWritable> Index<RangeInclusive<usize>> for PacketWriter<'_, T> {
    type Output = <T as Index<RangeInclusive<usize>>>::Output;

    #[inline]
    fn index(&self, index: RangeInclusive<usize>) -> &Self::Output {
        self.writable.index(index)
    }
}

impl<T: PacketWritable> Index<RangeTo<usize>> for PacketWriter<'_, T> {
    type Output = <T as Index<RangeTo<usize>>>::Output;

    #[inline]
    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        self.writable.index(index)
    }
}

pub trait PacketWritable:
    Index<usize>
    + Index<Range<usize>>
    + Index<RangeFrom<usize>>
    + Index<RangeInclusive<usize>>
    + Index<RangeTo<usize>>
{
    /// Writes the data to the writer at its current index.
    fn write_slice(&mut self, data: &[u8]) -> Result<(), IndexedWriteError>;

    /// Writes the data at the specified index position.
    ///
    /// This method will panic if `pos` is greater than the current written length of the buffer.
    fn write_slice_at(&mut self, data: &[u8], pos: usize) -> Result<(), IndexedWriteError>;

    /// Returns the current length of bytes written to the writer.
    ///
    /// Note that this is NOT the amount of available space the writer has left to write to.
    /// is
    fn len(&self) -> usize;

    /// Shifts the writer's index back to the provided index position, truncating the stream.
    ///
    /// This method will panic if `pos` is greater than the current written length of the buffer.
    fn truncate(&mut self, pos: usize) -> Result<(), IndexedWriteError>;
}

impl PacketWritable for Vec<u8> {
    #[inline]
    fn write_slice(&mut self, data: &[u8]) -> Result<(), IndexedWriteError> {
        self.extend(data);
        Ok(())
    }

    #[inline]
    fn write_slice_at(&mut self, data: &[u8], pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            return Err(IndexedWriteError::OutOfRange);
        }

        let split = cmp::max(self.len() - pos, data.len());

        self[pos..pos + split].copy_from_slice(&data[..split]);
        self.extend(&data[split..]);
        Ok(())
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn truncate(&mut self, pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            Err(IndexedWriteError::OutOfRange)
        } else {
            self.truncate(pos);
            Ok(())
        }
    }
}

impl<const N: usize> PacketWritable for Buffer<u8, N> {
    #[inline]
    fn write_slice(&mut self, slice: &[u8]) -> Result<(), IndexedWriteError> {
        if self.remaining() < slice.len() {
            return Err(IndexedWriteError::InsufficientBytes);
        }

        self.append(slice);
        Ok(())
    }

    #[inline]
    fn write_slice_at(&mut self, slice: &[u8], pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            return Err(IndexedWriteError::OutOfRange);
        }

        let split = cmp::max(self.len() - pos, slice.len());

        if self.remaining() < slice.len() - split {
            return Err(IndexedWriteError::InsufficientBytes);
        }

        self.as_mut_slice()[pos..pos + split].copy_from_slice(&slice[..split]);
        self.append(&slice[split..]);
        Ok(())
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn truncate(&mut self, pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            Err(IndexedWriteError::OutOfRange)
        } else {
            self.truncate(pos);
            Ok(())
        }
    }
}

impl PacketWritable for BufferMut<'_> {
    #[inline]
    fn write_slice(&mut self, slice: &[u8]) -> Result<(), IndexedWriteError> {
        if self.remaining() < slice.len() {
            return Err(IndexedWriteError::InsufficientBytes);
        }

        self.append(slice);
        Ok(())
    }

    #[inline]
    fn write_slice_at(&mut self, slice: &[u8], pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            return Err(IndexedWriteError::OutOfRange);
        }

        let split = cmp::max(self.len() - pos, slice.len());

        if self.remaining() < slice.len() - split {
            return Err(IndexedWriteError::InsufficientBytes);
        }

        self.as_mut_slice()[pos..pos + split].copy_from_slice(&slice[..split]);
        self.append(&slice[split..]);
        Ok(())
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn truncate(&mut self, pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            Err(IndexedWriteError::OutOfRange)
        } else {
            self.truncate(pos);
            Ok(())
        }
    }
}

/// An error in performing an indexed write.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum IndexedWriteError {
    /// An attempted indexed write would write beyond the end of the writer's buffer.
    OutOfRange,
    /// An attempted write failed due to the underlying writable running out of storage space.
    InsufficientBytes,
}
