//! Small checked ASCII delimiters, without linking core's unrelated general string machinery.
pub fn contains(text: &str, byte: u8) -> bool {
    text.as_bytes().iter().any(|value| *value == byte)
}
pub fn split_once(text: &str, delimiter: u8) -> Option<(&str, &str)> {
    let index = text
        .as_bytes()
        .iter()
        .position(|value| *value == delimiter)?;
    // An ASCII delimiter cannot occur inside a multibyte UTF-8 code point.
    if !delimiter.is_ascii() {
        return None;
    }
    Some(unsafe {
        (
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(text.as_ptr(), index)),
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                text.as_ptr().add(index + 1),
                text.len() - index - 1,
            )),
        )
    })
}
pub struct Split<'a> {
    text: Option<&'a str>,
    delimiter: u8,
}
pub fn split(text: &str, delimiter: u8) -> Split<'_> {
    Split {
        text: Some(text),
        delimiter,
    }
}
impl<'a> Iterator for Split<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        let text = self.text.take()?;
        match split_once(text, self.delimiter) {
            Some((head, tail)) => {
                self.text = Some(tail);
                Some(head)
            }
            None => Some(text),
        }
    }
}
pub fn text(bytes: &[u8]) -> Option<&str> {
    if !bytes.is_ascii() {
        return None;
    }
    Some(unsafe { core::str::from_utf8_unchecked(bytes) })
}
