use serde::de::{Deserialize, Deserializer};
use std::borrow::Cow;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Error as IoError, Lines, Read};
use std::iter::FusedIterator;
use std::path::{Path, PathBuf};

/// Wrapper type for a list of string values.
///
/// These lists are often used in configuration, and can contain either literal string values, or
/// string paths prefixed with `@`. This type implements `Deserialize`, and can then be iterated to
/// produce a combined list of all values from all literals and files.
#[derive(Default)]
pub struct StringList {
    inner: Vec<StringListEntry>,
}

enum StringListEntry {
    Literal(String),
    File(PathBuf),
}

impl From<Vec<String>> for StringList {
    fn from(input: Vec<String>) -> Self {
        let inner = input
            .into_iter()
            .map(|value| match value.strip_prefix('@') {
                Some(value) => StringListEntry::File(value.into()),
                None => StringListEntry::Literal(value),
            })
            .collect();
        Self { inner }
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input: Vec<String> = Deserialize::deserialize(deserializer)?;
        Ok(input.into())
    }
}

impl StringList {
    /// Iterate values in the list.
    pub fn iter_values(&self) -> StringListIter {
        StringListIter {
            list: self,
            index: 0,
            reader: None,
        }
    }
}

/// Iterator over values in a `StringList`.
///
/// Produces results that may contain IO errors from opening or reading files. Each result is
/// accompanied by a `StringListSource` that describes where it comes from.
pub struct StringListIter<'a> {
    list: &'a StringList,
    index: usize,
    reader: Option<StringListReader<'a, File>>,
}

impl<'a> Iterator for StringListIter<'a> {
    type Item = (StringListSource<'a>, Result<Cow<'a, str>, IoError>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Exhaust any open reader.
            if let Some(ref mut reader) = self.reader {
                if let Some(res) = reader.next() {
                    return Some((
                        StringListSource::File {
                            index: self.index,
                            path: reader.path,
                            line: reader.line,
                        },
                        match res {
                            Ok(data) => Ok(data.into()),
                            Err(err) => Err(err),
                        },
                    ));
                }
                self.reader = None;
                self.index += 1;
            }

            match self.list.inner.get(self.index)? {
                StringListEntry::Literal(ref data) => {
                    let source = StringListSource::Literal { index: self.index };
                    self.index += 1;
                    return Some((source, Ok(data.into())));
                }
                StringListEntry::File(ref path) => {
                    self.reader = match StringListReader::open(path) {
                        Ok(reader) => Some(reader),
                        Err(err) => {
                            return Some((
                                StringListSource::File {
                                    index: self.index,
                                    path,
                                    line: 0,
                                },
                                Err(err),
                            ));
                        }
                    };
                }
            }
        }
    }
}

impl FusedIterator for StringListIter<'_> {}

/// Source of a `StringListIter` result.
pub enum StringListSource<'a> {
    /// Value comes from a literal in the list.
    Literal {
        /// Index in the list.
        index: usize,
    },
    /// Value comes from a file.
    File {
        /// Index in the list.
        index: usize,
        /// Path of the file.
        path: &'a Path,
        /// Line number in the file. (Starts counting at 1.)
        line: usize,
    },
}

impl fmt::Display for StringListSource<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StringListSource::Literal { index } => write!(f, "#{} (literal)", index + 1),
            StringListSource::File { index, path, line } if *line != 0 => {
                write!(f, "#{} {path:?}:{line}", index + 1)
            }
            StringListSource::File { index, path, .. } => {
                write!(f, "#{} {path:?}", index + 1)
            }
        }
    }
}

/// File reader for a generic list of string values.
///
/// The file contains one value per line. Empty lines are skipped. Comments start with `#` and can
/// both appear on their own line or follow a value on the same line.
pub struct StringListReader<'a, R> {
    inner: Lines<BufReader<R>>,
    path: &'a Path,
    line: usize,
}

impl<'a> StringListReader<'a, File> {
    /// Open a file for reading.
    pub fn open(path: &'a Path) -> Result<Self, IoError> {
        Ok(Self::new(File::open(path)?, path))
    }
}

impl<'a, R: Read> StringListReader<'a, R> {
    /// Create a string reader from a raw reader.
    pub fn new(inner: R, path: &'a Path) -> Self {
        Self {
            inner: BufReader::new(inner).lines(),
            path,
            line: 0,
        }
    }
}

impl<R: Read> Iterator for StringListReader<'_, R> {
    type Item = Result<String, IoError>;

    fn next(&mut self) -> Option<Self::Item> {
        for data in &mut self.inner {
            self.line += 1;

            let data = match data {
                Err(err) => return Some(Err(err)),
                Ok(data) => data,
            };

            if let Some(data) = data.split('#').next() {
                let data = data.trim();
                if !data.is_empty() {
                    return Some(Ok(data.to_owned()));
                }
            }
        }
        None
    }
}

impl<R: Read> FusedIterator for StringListReader<'_, R> {}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    const INPUT: &[u8] = b"\
simple
two words

# comment
  additional  spacing  # ignored
  # indented comment
unusual# comment # syntax
";

    const EXPECT: &[&str] = &["simple", "two words", "additional  spacing", "unusual"];

    #[test]
    fn test_reader() {
        let dummy_path = PathBuf::new();
        let mut input_reader = super::StringListReader::new(INPUT, &dummy_path);
        let mut expect_iter = EXPECT.iter();
        loop {
            let input_item = input_reader.next().map(Result::unwrap);
            let expect_item = expect_iter.next().map(|item| (*item).to_string());
            assert_eq!(input_item, expect_item);
            if input_item.is_none() {
                break;
            }
        }
    }
}
