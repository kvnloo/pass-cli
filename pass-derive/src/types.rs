/*
 *  Copyright (c) 2026 Proton AG
 *  This file is part of Proton AG and Proton Pass.
 *
 *  Proton Pass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Proton Pass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Proton Pass.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

//! Target-independent classification of the Rust types used in exported
//! signatures. Backends decide how each shape crosses their FFI boundary.

use syn::{GenericArgument, PathArguments, Type, TypePath};

/// The shape of a parameter or return type, as far as FFI conversion cares.
pub enum Shape<'a> {
    /// `()`.
    Unit,
    /// A type every target handles natively: `String`, `bool`, numbers,
    /// `Vec<u8>` and `Vec`s of those.
    Native(&'a Type),
    /// `&str`.
    Str,
    /// `&T`, with the shape of `T`.
    Ref(Box<Shape<'a>>),
    /// `Option<T>`, with the shape of `T`.
    Option(Box<Shape<'a>>),
    /// `Vec<T>` where `T` isn't native.
    Vec(&'a Type),
    /// Any other type: a domain struct/enum that must be `#[sdk_export]`ed.
    Custom(&'a Type),
}

const NATIVE: &[&str] = &[
    "String", "bool", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "usize",
    "isize",
];

pub fn shape(ty: &Type) -> Shape<'_> {
    match ty {
        Type::Tuple(tuple) if tuple.elems.is_empty() => Shape::Unit,
        Type::Reference(reference) => match &*reference.elem {
            Type::Path(path) if path.path.is_ident("str") => Shape::Str,
            inner => Shape::Ref(Box::new(shape(inner))),
        },
        Type::Path(path) if is_native(path) => Shape::Native(ty),
        Type::Path(path) => {
            if let Some(inner) = generic_arg(path, "Option") {
                Shape::Option(Box::new(shape(inner)))
            } else if let Some(inner) = generic_arg(path, "Vec") {
                match shape(inner) {
                    Shape::Native(_) => Shape::Native(ty),
                    _ => Shape::Vec(inner),
                }
            } else {
                Shape::Custom(ty)
            }
        }
        _ => Shape::Custom(ty),
    }
}

fn is_native(path: &TypePath) -> bool {
    path.qself.is_none()
        && path.path.segments.len() == 1
        && NATIVE.iter().any(|name| path.path.is_ident(name))
}

/// If `path` is `Name<T>` (or `a::b::Name<T>`), returns `T`.
pub fn generic_arg<'a>(path: &'a TypePath, name: &str) -> Option<&'a Type> {
    let segment = path.path.segments.last()?;
    if segment.ident != name {
        return None;
    }
    match &segment.arguments {
        PathArguments::AngleBracketed(args) => args.args.iter().find_map(|arg| match arg {
            GenericArgument::Type(ty) => Some(ty),
            _ => None,
        }),
        _ => None,
    }
}

/// Splits a return type into `(T, is_fallible)` for `Result<T, _>` / `T`.
pub fn unwrap_result(ty: &Type) -> (&Type, bool) {
    if let Type::Path(path) = ty
        && let Some(inner) = generic_arg(path, "Result")
    {
        return (inner, true);
    }
    (ty, false)
}

pub fn to_camel_case(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut upper = false;
    for c in snake.chars() {
        if c == '_' {
            upper = !out.is_empty();
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}
