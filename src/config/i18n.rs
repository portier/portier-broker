use gettext::Catalog;
use std::fs::File;
use std::path::PathBuf;

/// Contains all gettext catalogs we use in compiled form.
pub struct I18n {
    pub catalogs: Vec<(String, Catalog)>,
}

/// List of languages. Matches the contents of `lang/`.
///
/// NOTE: The list is matched in order, so list regional variants first.
const SUPPORTED_LANGUAGES: &[&str] = &["en", "de", "nl", "fr_CA", "fr"];

impl I18n {
    pub fn new(data_dir: &str) -> I18n {
        let data_dir: PathBuf = data_dir.into();
        let catalogs = SUPPORTED_LANGUAGES
            .iter()
            .map(|lang| {
                let mut path = data_dir.clone();
                path.push("lang");
                path.push(lang);
                path.set_extension("mo");
                let file = File::open(path).expect("could not open catalog file");
                let catalog = Catalog::parse(file).expect("could not parse catalog file");

                // `Accept-Language` header uses IETF format.
                let lang = lang.replace("_", "-");

                (lang, catalog)
            })
            .collect();
        I18n { catalogs }
    }
}
