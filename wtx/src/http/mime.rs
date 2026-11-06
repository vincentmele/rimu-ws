use crate::collections::ShortStrU8;

/// Used to specify the data type that is going to be sent to a counterpart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mime {
  /// application/grpc
  ApplicationGrpc,
  /// application/json
  ApplicationJson,
  /// application/octet-stream
  ApplicationOctetStream,
  /// application/pdf
  ApplicationPdf,
  /// application/vnd.google.protobuf
  ApplicationVndGoogleProtobuf,
  /// application/vnd.oasis.opendocument.spreadsheet
  ApplicationVndOasisOpendocumentSpreadsheet,
  /// application/wasm
  ApplicationWasm,
  /// application/xml
  ApplicationXml,
  /// application/x-www-form-urlencoded
  ApplicationXWwwFormUrlEncoded,
  /// application/yaml
  ApplicationYaml,
  /// application/zip
  ApplicationZip,
  /// audio/mpeg
  AudioMpeg,
  /// audio/ogg
  AudioOgg,
  /// audio/webm
  AudioWebm,
  /// Anything
  Custom(ShortStrU8<'static>),
  /// font/woff
  FontWoff,
  /// font/woff2
  FontWoff2,
  /// image/avif
  ImageAvif,
  /// image/gif
  ImageGif,
  /// image/jpeg
  ImageJpeg,
  /// image/png
  ImagePng,
  /// image/svg+xml
  ImageSvgXml,
  /// image/webp
  ImageWebp,
  /// image/x-icon
  ImageXIcon,
  /// multipart/form-data
  MultipartFormData,
  /// text/css
  TextCss,
  /// text/csv
  TextCsv,
  /// text/html
  TextHtml,
  /// text/javascript
  TextJavascript,
  /// text/markdown
  TextMarkdown,
  /// text/plain
  TextPlain,
  /// video/mp4
  VideoMp4,
  /// video/mpeg
  VideoMpeg,
  /// video/webm
  VideoWebm,
}

impl Mime {
  /// The type of a file by its extension, without the dot and in any case. `None` for an
  /// extension outside the table.
  #[inline]
  pub fn from_extension(ext: &str) -> Option<Self> {
    let mut buffer = [0u8; 8];
    let lower = buffer.get_mut(..ext.len())?;
    lower.copy_from_slice(ext.as_bytes());
    lower.make_ascii_lowercase();
    Some(match &*lower {
      b"avif" => Self::ImageAvif,
      b"css" => Self::TextCss,
      b"csv" => Self::TextCsv,
      b"gif" => Self::ImageGif,
      b"htm" | b"html" => Self::TextHtml,
      b"ico" => Self::ImageXIcon,
      b"jpeg" | b"jpg" => Self::ImageJpeg,
      b"js" | b"mjs" => Self::TextJavascript,
      b"json" | b"map" => Self::ApplicationJson,
      b"md" => Self::TextMarkdown,
      b"mp3" => Self::AudioMpeg,
      b"mp4" => Self::VideoMp4,
      b"mpeg" => Self::VideoMpeg,
      b"oga" | b"ogg" => Self::AudioOgg,
      b"pdf" => Self::ApplicationPdf,
      b"png" => Self::ImagePng,
      b"svg" => Self::ImageSvgXml,
      b"txt" => Self::TextPlain,
      b"wasm" => Self::ApplicationWasm,
      b"webm" => Self::VideoWebm,
      b"webp" => Self::ImageWebp,
      b"woff" => Self::FontWoff,
      b"woff2" => Self::FontWoff2,
      b"xml" => Self::ApplicationXml,
      b"yaml" | b"yml" => Self::ApplicationYaml,
      b"zip" => Self::ApplicationZip,
      _ => return None,
    })
  }

  /// Common string representation.
  #[inline]
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::ApplicationGrpc => "application/grpc",
      Self::ApplicationJson => "application/json",
      Self::ApplicationOctetStream => "application/octet-stream",
      Self::ApplicationPdf => "application/pdf",
      Self::ApplicationVndGoogleProtobuf => "application/vnd.google.protobuf",
      Self::ApplicationVndOasisOpendocumentSpreadsheet => {
        "application/vnd.oasis.opendocument.spreadsheet"
      }
      Self::ApplicationWasm => "application/wasm",
      Self::ApplicationXml => "application/xml",
      Self::ApplicationXWwwFormUrlEncoded => "application/x-www-form-urlencoded",
      Self::ApplicationYaml => "application/yaml",
      Self::ApplicationZip => "application/zip",
      Self::AudioMpeg => "audio/mpeg",
      Self::AudioOgg => "audio/ogg",
      Self::AudioWebm => "audio/webm",
      Self::Custom(el) => el.into_str(),
      Self::FontWoff => "font/woff",
      Self::FontWoff2 => "font/woff2",
      Self::ImageAvif => "image/avif",
      Self::ImageGif => "image/gif",
      Self::ImageJpeg => "image/jpeg",
      Self::ImagePng => "image/png",
      Self::ImageSvgXml => "image/svg+xml",
      Self::ImageWebp => "image/webp",
      Self::ImageXIcon => "image/x-icon",
      Self::MultipartFormData => "multipart/form-data",
      Self::TextCss => "text/css",
      Self::TextCsv => "text/csv",
      Self::TextHtml => "text/html",
      Self::TextJavascript => "text/javascript",
      Self::TextMarkdown => "text/markdown",
      Self::TextPlain => "text/plain",
      Self::VideoMp4 => "video/mp4",
      Self::VideoMpeg => "video/mpeg",
      Self::VideoWebm => "video/webm",
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::http::Mime;

  #[test]
  fn mime_from_extension() {
    assert_eq!(Mime::from_extension("css"), Some(Mime::TextCss));
    assert_eq!(Mime::from_extension("JS"), Some(Mime::TextJavascript));
    assert_eq!(Mime::from_extension("woff2"), Some(Mime::FontWoff2));
    assert_eq!(Mime::from_extension("json"), Some(Mime::ApplicationJson));
    assert_eq!(Mime::from_extension("tar"), None);
    assert_eq!(Mime::from_extension("averyverylongext"), None);
    assert_eq!(Mime::from_extension(""), None);
  }
}
