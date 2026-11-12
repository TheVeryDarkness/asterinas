// SPDX-License-Identifier: MPL-2.0

//! Source-preserving insertion of safe function-boundary calls.

use proc_macro2::{LineColumn, Span};
use quote::{ToTokens, quote};
use syn::{
    Attribute, Block, FnArg, GenericArgument, ImplItem, Item, Pat, PathArguments, ReturnType,
    Signature, TraitItem, Type, visit::Visit,
};

use crate::{Config, FieldReport, FunctionReport, InstrumentError, Report};

/// Matches `aster_rsm::hooks::MAX_PAYLOAD_VALUES` in the runtime event ABI.
///
/// This build-time tool deliberately does not depend on the kernel runtime.
/// Generated array types are checked against its API during the kernel build.
const MAX_PAYLOAD_VALUES: usize = 4;

pub(super) fn instrument(
    source: &str,
    relative_path: &str,
    config: &Config,
) -> Result<(String, Report), InstrumentError> {
    let file = syn::parse_file(source)?;
    let mut transformer = Transformer {
        source,
        relative_path,
        config,
        line_offsets: line_offsets(source),
        edits: Vec::new(),
        report: Report::default(),
    };
    let module = relative_path
        .strip_suffix(".rs")
        .unwrap_or(relative_path)
        .trim_end_matches("/mod")
        .replace('/', "::");
    transformer.items(&file.items, &module, has_lint_expectation(&file.attrs))?;
    transformer.edits.sort_by_key(|edit| edit.start);
    let mut generated = source.to_owned();
    for edit in transformer.edits.into_iter().rev() {
        generated.replace_range(edit.start..edit.end, &edit.replacement);
    }
    Ok((generated, transformer.report))
}

struct Edit {
    start: usize,
    end: usize,
    replacement: String,
}

struct Transformer<'a> {
    source: &'a str,
    relative_path: &'a str,
    config: &'a Config,
    line_offsets: Vec<usize>,
    edits: Vec<Edit>,
    report: Report,
}

impl Transformer<'_> {
    fn items(
        &mut self,
        items: &[Item],
        module: &str,
        inherited_expectation: bool,
    ) -> Result<(), InstrumentError> {
        for item in items {
            match item {
                Item::Fn(function) => {
                    self.function(
                        &function.sig,
                        &function.attrs,
                        &function.block,
                        module,
                        &function.sig.ident.to_string(),
                        inherited_expectation.then_some("lint expectation scope"),
                    )?;
                }
                Item::Mod(nested) => {
                    if let Some((_, items)) = &nested.content {
                        self.items(
                            items,
                            &format!("{module}::{}", nested.ident),
                            inherited_expectation || has_lint_expectation(&nested.attrs),
                        )?;
                    }
                }
                Item::Impl(implementation) => {
                    let self_type = compact(&implementation.self_ty);
                    let drop_impl = implementation
                        .trait_
                        .as_ref()
                        .and_then(|(_, path, _)| path.segments.last())
                        .is_some_and(|segment| segment.ident == "Drop");
                    let canonical_impl = implementation
                        .trait_
                        .as_ref()
                        .and_then(|(_, path, _)| path.segments.last())
                        .is_some_and(|segment| {
                            segment.ident == "Clone" || segment.ident == "PartialOrd"
                        });
                    let owner = match &implementation.trait_ {
                        Some((_, path, _)) => format!("<{self_type} as {}>", compact(path)),
                        None => self_type,
                    };
                    for item in &implementation.items {
                        if let ImplItem::Fn(function) = item {
                            self.function(
                                &function.sig,
                                &function.attrs,
                                &function.block,
                                module,
                                &format!("{owner}::{}", function.sig.ident),
                                if inherited_expectation
                                    || has_lint_expectation(&implementation.attrs)
                                {
                                    Some("lint expectation scope")
                                } else {
                                    drop_impl.then_some("destructor").or_else(|| {
                                        canonical_impl.then_some("canonical trait implementation")
                                    })
                                },
                            )?;
                        }
                    }
                }
                Item::Trait(definition) => {
                    for item in &definition.items {
                        if let TraitItem::Fn(function) = item
                            && let Some(body) = &function.default
                        {
                            self.function(
                                &function.sig,
                                &function.attrs,
                                body,
                                module,
                                &format!("{}::{}", definition.ident, function.sig.ident),
                                Some("trait default method"),
                            )?;
                        }
                    }
                }
                // Item macros and nested functions inside a body are left intact.
                // Their control flow belongs to their own compiler expansion.
                _ => {}
            }
        }
        Ok(())
    }

    fn function(
        &mut self,
        signature: &Signature,
        attributes: &[Attribute],
        body: &Block,
        module: &str,
        suffix: &str,
        exclusion: Option<&str>,
    ) -> Result<(), InstrumentError> {
        let name = format!("{module}::{suffix}");
        let exclusion = exclusion
            .map(str::to_owned)
            .or_else(|| unsupported_signature(signature, attributes))
            .or_else(|| (!self.config.selects_function(&name)).then(|| "function filter".into()));
        let mut report = FunctionReport {
            source: self.relative_path.to_owned(),
            line: signature.fn_token.span.start().line,
            function: name,
            instrumented: exclusion.is_none(),
            reason: exclusion,
            entry_fields: Vec::new(),
            return_fields: Vec::new(),
            omitted_arguments: Vec::new(),
        };
        if !report.instrumented {
            self.report.functions.push(report);
            return Ok(());
        }

        let mut inputs = Vec::new();
        let mut closure_parameters = Vec::new();
        let mut closure_arguments = Vec::new();
        let mut has_receiver = false;
        for argument in &signature.inputs {
            let FnArg::Typed(argument) = argument else {
                has_receiver = true;
                report.omitted_arguments.push("self: receiver".into());
                continue;
            };
            let Pat::Ident(pattern) = &*argument.pat else {
                report.omitted_arguments.push(format!(
                    "{}: destructured parameter",
                    compact(&argument.pat)
                ));
                continue;
            };
            let identifier = &pattern.ident;
            let ty = &argument.ty;
            let mutable = &pattern.mutability;
            closure_parameters.push(quote!(#mutable #identifier: #ty).to_string());
            closure_arguments.push(identifier.to_string());
            if let Some(mutable) = pattern.mutability {
                // The binding that the original body mutates now belongs to the
                // closure. Its outer forwarding parameter is no longer mutable.
                self.edits.push(Edit {
                    start: self.offset(mutable.span.start())?,
                    end: self.offset(mutable.span.end())?,
                    replacement: String::new(),
                });
            }
            let name = pattern.ident.to_string();
            if pattern.by_ref.is_some() || pattern.subpat.is_some() {
                report
                    .omitted_arguments
                    .push(format!("{name}: borrowed pattern"));
            } else if inputs.len() == MAX_PAYLOAD_VALUES {
                report
                    .omitted_arguments
                    .push(format!("{name}: payload capacity"));
            } else if scalar(&argument.ty) {
                inputs.push(scalar_expression(&identifier.to_string(), &argument.ty));
                report.entry_fields.push(FieldReport {
                    name,
                    ty: compact(&argument.ty),
                });
            } else {
                report.omitted_arguments.push(format!(
                    "{name}: unsupported payload type {}",
                    compact(&argument.ty)
                ));
            }
        }

        let start = self.offset(body.brace_token.span.open().start())?;
        let end = self.offset(body.brace_token.span.close().end())?;
        let original = &self.source[start + 1..end - 1];
        // Typed closure arguments preserve parameter destruction order. The
        // receiver is its only capture, and forcing a whole-self capture avoids
        // disjoint-field capture changing the destruction order of owned fields.
        let receiver_capture = if has_receiver { "let _ = &self;" } else { "" };
        let namespace = self.fresh_namespace(start);
        let result = format!("{namespace}_result");
        let (outputs, fields) = return_payload(&signature.output, &result);
        report.return_fields = fields;
        let output_type = match &signature.output {
            ReturnType::Default => "()".to_owned(),
            ReturnType::Type(_, ty) => ty.to_token_stream().to_string(),
        };
        let entry_fields = fields_expression(&report.entry_fields);
        let return_fields = fields_expression(&report.return_fields);
        let suffix = syn::LitStr::new(suffix, Span::call_site());
        let replacement = format!(
            "{{\n\
             let {namespace}_hook = ::aster_rsm::function_hook!({suffix}, {entry_fields}, {return_fields});\n\
             let {namespace}_invocation = {namespace}_hook.enter({inputs});\n\
             #[expect(clippy::allow_attributes, reason = \"the closure lint does not fire for every supported body, so a narrow allow is required\")]\n\
             #[allow(clippy::redundant_closure_call, reason = \"preserves return and question-mark paths for the generated normal-return hook\")]\n\
             let {result}: {output_type} = (move |{parameters}| -> {output_type} {{ {receiver_capture} {original} }})({arguments});\n\
             {namespace}_invocation.finish({outputs});\n\
             {result}\n\
             }}",
            suffix = suffix.to_token_stream(),
            parameters = closure_parameters.join(", "),
            arguments = closure_arguments.join(", "),
            inputs = padded_payload(inputs),
            outputs = padded_payload(outputs),
        );
        self.edits.push(Edit {
            start,
            end,
            replacement,
        });
        self.report.functions.push(report);
        Ok(())
    }

    fn offset(&self, position: LineColumn) -> Result<usize, InstrumentError> {
        let start = *self
            .line_offsets
            .get(position.line.saturating_sub(1))
            .ok_or("invalid source span line")?;
        // proc-macro2 columns count Unicode scalar values rather than UTF-8 bytes.
        let offset = self.source[start..]
            .char_indices()
            .nth(position.column)
            .map(|(offset, _)| start + offset)
            .unwrap_or(self.source.len());
        Ok(offset)
    }

    fn fresh_namespace(&self, position: usize) -> String {
        let mut namespace = format!("__rsm_generated_{position}");
        while self.source.contains(&namespace) {
            namespace.push('_');
        }
        namespace
    }
}

fn unsupported_signature(signature: &Signature, attributes: &[Attribute]) -> Option<String> {
    let reason = if signature.constness.is_some() {
        "const function"
    } else if signature.asyncness.is_some() {
        "async function"
    } else if signature.unsafety.is_some() {
        "unsafe function"
    } else if signature.abi.is_some() || signature.variadic.is_some() {
        "foreign ABI"
    } else if attributes.iter().any(|attribute| matches!(attribute.style, syn::AttrStyle::Inner(_))) {
        "inner function attribute"
    } else if has_lint_expectation(attributes) {
        "lint expectation scope"
    } else if signature.inputs.iter().any(|argument| match argument {
        FnArg::Receiver(receiver) => !receiver.attrs.is_empty(),
        FnArg::Typed(argument) => {
            !argument.attrs.is_empty()
                || !matches!(&*argument.pat, Pat::Ident(pattern) if pattern.by_ref.is_none() && pattern.subpat.is_none())
        }
    }) {
        "non-forwardable parameter pattern"
    } else if signature.inputs.iter().any(|argument| match argument {
        FnArg::Receiver(_) => false,
        FnArg::Typed(argument) => {
            let mut visitor = UnsupportedParameter::default();
            visitor.visit_type(&argument.ty);
            visitor.is_opaque
        }
    }) {
        "opaque parameter type"
    } else if attributes.iter().any(|attribute| {
        let text = compact(&attribute.meta);
        text.contains("track_caller") || text.contains("naked") || text.contains("ktest")
    }) {
        "special function attribute"
    } else {
        let mut visitor = UnsupportedReturn::default();
        if let ReturnType::Type(_, ty) = &signature.output {
            visitor.visit_type(ty);
        }
        return visitor.reason.map(str::to_owned);
    };
    Some(reason.to_owned())
}

#[derive(Default)]
struct UnsupportedParameter {
    is_opaque: bool,
}

impl<'ast> Visit<'ast> for UnsupportedParameter {
    fn visit_type_impl_trait(&mut self, _: &'ast syn::TypeImplTrait) {
        self.is_opaque = true;
    }
}

#[derive(Default)]
struct UnsupportedReturn {
    reason: Option<&'static str>,
}

impl<'ast> Visit<'ast> for UnsupportedReturn {
    fn visit_lifetime(&mut self, lifetime: &'ast syn::Lifetime) {
        if lifetime.ident != "static" {
            self.reason = Some("lifetime-bearing return type");
        }
    }

    fn visit_type_reference(&mut self, _: &'ast syn::TypeReference) {
        self.reason = Some("reference-containing return type");
    }

    fn visit_type_impl_trait(&mut self, _: &'ast syn::TypeImplTrait) {
        self.reason = Some("opaque return type");
    }

    fn visit_type_never(&mut self, _: &'ast syn::TypeNever) {
        self.reason = Some("diverging return type");
    }
}

fn scalar(ty: &Type) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return false;
    }
    let segment = &path.path.segments[0];
    if !matches!(segment.arguments, PathArguments::None) {
        return false;
    }
    matches!(
        segment.ident.to_string().as_str(),
        "u8" | "u16"
            | "u32"
            | "u64"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "isize"
            | "bool"
            | "char"
            | "Vaddr"
            | "RawFileDesc"
            | "Pid"
            | "Tid"
    )
}

fn scalar_expression(value: &str, ty: &Type) -> String {
    if compact(ty) == "u64" {
        value.to_owned()
    } else {
        format!("{value} as u64")
    }
}

fn return_payload(output: &ReturnType, result: &str) -> (Vec<String>, Vec<FieldReport>) {
    let ReturnType::Type(_, ty) = output else {
        return (Vec::new(), Vec::new());
    };
    if scalar(ty) {
        return (
            vec![scalar_expression(result, ty)],
            vec![FieldReport {
                name: "return".into(),
                ty: compact(ty),
            }],
        );
    }
    let Type::Path(path) = &**ty else {
        return (Vec::new(), Vec::new());
    };
    let Some(segment) = path
        .path
        .segments
        .last()
        .filter(|segment| segment.ident == "Result")
    else {
        return (Vec::new(), Vec::new());
    };
    let mut values = vec![format!("u64::from({result}.is_err())")];
    let mut fields = vec![FieldReport {
        name: "is_error".into(),
        ty: "bool".into(),
    }];
    if let PathArguments::AngleBracketed(arguments) = &segment.arguments
        && let Some(GenericArgument::Type(success)) = arguments.args.first()
        && scalar(success)
    {
        let value = scalar_expression("*value", success);
        values.push(format!(
            "match &{result} {{ ::core::result::Result::Ok(value) => {value}, ::core::result::Result::Err(_) => 0 }}"
        ));
        fields.push(FieldReport {
            name: "ok".into(),
            ty: compact(success),
        });
    }
    (values, fields)
}

fn padded_payload(mut values: Vec<String>) -> String {
    values.resize(MAX_PAYLOAD_VALUES, "0".into());
    format!("[{}]", values.join(", "))
}

fn fields_expression(fields: &[FieldReport]) -> String {
    let fields = fields.iter().map(|field| {
        let name = &field.name;
        let ty = &field.ty;
        quote!(::aster_rsm::hooks::Field::new(#name, #ty))
    });
    quote!(&[#(#fields),*]).to_string()
}

fn line_offsets(source: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(source.match_indices('\n').map(|(offset, _)| offset + 1))
        .collect()
}

fn compact(tokens: &impl ToTokens) -> String {
    tokens.to_token_stream().to_string().replace(' ', "")
}

fn has_lint_expectation(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("expect")
            || (attribute.path().is_ident("cfg_attr")
                && compact(&attribute.meta).contains(",expect("))
    })
}
