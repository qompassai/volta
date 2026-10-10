// #################################################################
// /qompassai/volta/src/i18n.rs
// Qompass AI I18n
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// This file was authored by Qompass AI and is dual-licensed
// under AGPL-3.0 or Apache-2.0 at the recipient's choice
// (see LICENSE-AGPL, LICENSE, and NOTICE). Volta as a whole
// is Hagrid-derived and distributed under AGPL-3.0; the
// Apache choice applies to Qompass-authored material only.

use handlebars::{
    Context, Handlebars, Helper, HelperDef, HelperResult, Output, RenderContext, RenderError,
};

pub struct I18NHelper {
    catalogs: Vec<(&'static str, gettext::Catalog)>,
}

impl I18NHelper {
    pub fn new(catalogs: Vec<(&'static str, gettext::Catalog)>) -> Self {
        Self { catalogs }
    }

    pub fn get_catalog(&self, lang: &str) -> &gettext::Catalog {
        let (_, catalog) = self
            .catalogs
            .iter()
            .find(|(candidate, _)| *candidate == lang)
            .unwrap_or_else(|| self.catalogs.first().unwrap());
        catalog
    }

    // Traverse the fallback chain,
    pub fn lookup<'a>(
        &'a self,
        lang: &str,
        text_id: &'a str,
        // args: Option<&HashMap<&str, FluentValue>>,
    ) -> &'a str {
        let catalog = self.get_catalog(lang);
        catalog.gettext(text_id)
        // format!("Unknown localization {}", text_id)
    }
}

impl HelperDef for I18NHelper {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'reg, 'rc>,
        reg: &'reg Handlebars,
        context: &'rc Context,
        rcx: &mut RenderContext<'reg, '_>,
        out: &mut dyn Output,
    ) -> HelperResult {
        let id = if let Some(id) = h.param(0) {
            id
        } else {
            return Err(RenderError::new(
                "{{text}} must have at least one parameter",
            ));
        };

        let id = if let Some(id) = id.value().as_str() {
            id
        } else {
            return Err(RenderError::new("{{text}} takes an identifier parameter"));
        };

        let rerender = h
            .param(1)
            .and_then(|p| p.relative_path().map(|v| v == "rerender"))
            .unwrap_or(false);

        let lang = context
            .data()
            .get("lang")
            .expect("Language not set in context")
            .as_str()
            .expect("Language must be string");

        fn render_error_with<E>(e: E) -> RenderError
        where
            E: std::error::Error + Send + Sync + 'static,
        {
            RenderError::from_error("Failed to render", e)
        }
        let response = self.lookup(lang, id);
        if rerender {
            let data = rcx.evaluate(context, "this").unwrap();
            let response = reg
                .render_template(response, data.as_json())
                .map_err(render_error_with)?;
            out.write(&response).map_err(render_error_with)?;
        } else {
            out.write(response).map_err(render_error_with)?;
        }
        Ok(())
    }
}

/// The per-request localization context, selected from the
/// `Accept-Language` header against the catalogs managed by Rocket
/// (see `web::get_i18n`). This replaces the `rocket_i18n` git
/// dependency (GPL-3.0, pinned to a pre-release Rocket API whose
/// `Outcome::Failure` variant no longer exists) with an in-tree
/// implementation of the same selection contract.
/// The managed catalog set: (language tag, catalog) pairs.
pub type Translations = Vec<(&'static str, gettext::Catalog)>;

pub struct I18n {
    pub catalog: gettext::Catalog,
    pub lang: &'static str,
}

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for I18n {
    type Error = ();

    async fn from_request(
        req: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        use rocket::http::Status;
        use rocket::request::Outcome;

        let Some(langs) = req
            .rocket()
            .state::<Vec<(&'static str, gettext::Catalog)>>()
        else {
            return Outcome::Error((Status::InternalServerError, ()));
        };

        let lang = req
            .headers()
            .get_one("Accept-Language")
            .unwrap_or("en")
            .split(',')
            .filter_map(|candidate| candidate.split(['-', ';']).next())
            .find(|candidate| langs.iter().any(|(supported, _)| supported == candidate))
            .unwrap_or("en");

        match langs.iter().find(|(supported, _)| *supported == lang) {
            Some((supported, catalog)) => Outcome::Success(I18n {
                catalog: catalog.clone(),
                lang: supported,
            }),
            None => Outcome::Error((Status::InternalServerError, ())),
        }
    }
}
