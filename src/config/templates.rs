use std::path::PathBuf;

// Newtype so we can implement helpers for templates.
#[derive(Clone)]
pub struct Template(mustache::Template);

impl Template {
    fn compile(data_dir: &str, name: &str) -> Template {
        let mut path: PathBuf = data_dir.into();
        path.push("tmpl");
        path.push(name);
        path.set_extension("mustache");
        Template(
            mustache::compile_path(&path)
                .unwrap_or_else(|err| panic!("unable to compile template {path:?}: {err:?}")),
        )
    }

    pub fn render(&self, params: &[(&str, &str)]) -> String {
        let mut builder = mustache::MapBuilder::new();
        for &param in params {
            let (key, value) = param;
            builder = builder.insert_str(key, value);
        }
        self.render_data(&builder.build())
    }

    pub fn render_data(&self, data: &mustache::Data) -> String {
        let mut out: Vec<u8> = Vec::new();
        self.0
            .render_data(&mut out, data)
            .expect("unable to render template");
        String::from_utf8(out).expect("unable to render template as string")
    }
}

// Contains all templates we use in compiled form.
pub struct Templates {
    /// Page displayed when the confirmation email was sent.
    pub confirm_email: Template,
    /// Page displayed when following an email confirmation link from a new device..
    pub confirm_device: Template,
    /// Page displayed when the `login_hint` is missing.
    pub login_hint: Template,
    /// HTML formatted email containing the one-type pad.
    pub email_html: Template,
    /// Plain text email containing the one-type pad.
    pub email_text: Template,
    /// The error page template.
    pub error: Template,
    /// A dummy form used to redirect back to the RP with a POST request.
    pub forward: Template,
    /// A dummy form used to capture query and fragment parameters.
    pub rewrite_to_post: Template,
}

impl Templates {
    pub fn new(data_dir: &str) -> Templates {
        Templates {
            confirm_email: Template::compile(data_dir, "confirm_email"),
            confirm_device: Template::compile(data_dir, "confirm_device"),
            email_html: Template::compile(data_dir, "email_html"),
            email_text: Template::compile(data_dir, "email_text"),
            login_hint: Template::compile(data_dir, "login_hint"),
            error: Template::compile(data_dir, "error"),
            forward: Template::compile(data_dir, "forward"),
            rewrite_to_post: Template::compile(data_dir, "rewrite_to_post"),
        }
    }
}
