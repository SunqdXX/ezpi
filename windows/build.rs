//! Embeds the icon, the manifest (per-monitor DPI; no elevation, see src/install.rs) and the
//! version info.

include!("src/art.rs");

fn main() {
    println!("cargo::rerun-if-changed=src/art.rs");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let ico = out.join("ezpi.ico");
    std::fs::write(&ico, ico_file()).unwrap();
    let level = "asInvoker";
    let manifest = out.join("ezpi.manifest");
    std::fs::write(
        &manifest,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="EzPi" version="1.0.0.0"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="{level}" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application><supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/></application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#
        ),
    )
    .unwrap();
    let ver = env!("CARGO_PKG_VERSION").replace('.', ",");
    let esc = |p: &std::path::Path| p.display().to_string().replace('\\', "\\\\");
    let rc = out.join("ezpi.rc");
    std::fs::write(
        &rc,
        format!(
            r#"1 ICON "{ico}"
1 24 "{manifest}"
1 VERSIONINFO
FILEVERSION {ver},0
PRODUCTVERSION {ver},0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "FileDescription", "EzPi"
      VALUE "ProductName", "EzPi"
      VALUE "FileVersion", "{v}"
      VALUE "ProductVersion", "{v}"
      VALUE "LegalCopyright", "MIT License"
      VALUE "OriginalFilename", "EzPi.exe"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
            ico = esc(&ico),
            manifest = esc(&manifest),
            v = env!("CARGO_PKG_VERSION"),
        ),
    )
    .unwrap();
    embed_resource::compile_for(&rc, ["EzPi"], embed_resource::NONE)
        .manifest_required()
        .unwrap();
}

fn ico_file() -> Vec<u8> {
    ico(&[16, 20, 24, 32, 40, 48, 64, 128], true)
}
