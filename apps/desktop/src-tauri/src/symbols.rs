//! SF Symbols for the desktop shell.
//!
//! The web view cannot address the system symbol font directly, so AppKit
//! renders the symbol to a black-on-transparent PNG and the shell masks it
//! with the current text colour. Symbols are used only inside this Mac app.

#[cfg(target_os = "macos")]
fn render(name: &str, point_size: f64, weight: &str, scale: f64) -> Option<String> {
    use base64::Engine;
    use objc2_app_kit::{
        NSBitmapImageFileType, NSBitmapImageRep, NSFontWeightMedium, NSFontWeightRegular,
        NSFontWeightSemibold, NSImage, NSImageSymbolConfiguration, NSImageSymbolScale,
    };
    use objc2_foundation::{NSDictionary, NSSize, NSString};

    let image = NSImage::imageWithSystemSymbolName_accessibilityDescription(
        &NSString::from_str(name),
        None,
    )?;
    let weight = unsafe {
        match weight {
            "regular" => NSFontWeightRegular,
            "semibold" => NSFontWeightSemibold,
            _ => NSFontWeightMedium,
        }
    };
    let configuration = NSImageSymbolConfiguration::configurationWithPointSize_weight_scale(
        point_size,
        weight,
        NSImageSymbolScale::Medium,
    );
    let image = image.imageWithSymbolConfiguration(&configuration)?;
    let size = image.size();
    // Rasterise at the display scale so the mask stays crisp on Retina.
    image.setSize(NSSize::new(size.width * scale, size.height * scale));
    let tiff = image.TIFFRepresentation()?;
    let representation = NSBitmapImageRep::imageRepWithData(&tiff)?;
    let png = unsafe {
        representation
            .representationUsingType_properties(NSBitmapImageFileType::PNG, &NSDictionary::new())
    }?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(png.to_vec());
    Some(format!("data:image/png;base64,{encoded}"))
}

/// Returns a data URL for the named SF Symbol, or `None` when the symbol
/// does not exist on this macOS version so the caller can fall back.
#[tauri::command]
pub(super) fn system_symbol(
    name: String,
    point_size: f64,
    weight: String,
    scale: f64,
) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        render(&name, point_size, &weight, scale)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (name, point_size, weight, scale);
        None
    }
}
