//! The window: plain Win32 drawn with Direct2D/DirectWrite (both part of Windows), a tray icon,
//! and nothing that runs while idle (the animation timer only ticks during a transition).
#![allow(unsafe_code)]

use std::{cell::RefCell, time::Instant};

use windows::{
    Win32::{
        Foundation::*,
        Graphics::{
            Direct2D::{Common::*, *},
            DirectWrite::*,
            Dwm::*,
            Dxgi::Common::DXGI_FORMAT_UNKNOWN,
            Gdi::*,
        },
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Controls::{MARGINS, WM_MOUSELEAVE},
            HiDpi::GetDpiForWindow,
            Input::KeyboardAndMouse::*,
            Shell::*,
            WindowsAndMessaging::*,
        },
    },
    core::{HSTRING, Interface, PCWSTR, w},
};
use windows_numerics::{Matrix3x2, Vector2};

use crate::app::{self, Power, Svc, WM_MODEL};

pub const CLASS: PCWSTR = w!("EzPiWindow");
pub const WM_SHOWME: u32 = WM_APP + 3;
const WM_TRAY: u32 = WM_APP + 1;
const TIMER: usize = 1;

const W: f32 = 340.0;
const H: f32 = 500.0;
const BAR: f32 = 40.0;
const C: (f32, f32) = (170.0, 232.0);
const R_BTN: f32 = 76.0;

const CMD_OPEN: usize = 1;
const CMD_TOGGLE: usize = 2;
const CMD_QUIT: usize = 3;
const CMD_UNINSTALL: usize = 4;

fn rgb(hex: u32, a: f32) -> D2D1_COLOR_F {
    D2D1_COLOR_F {
        r: ((hex >> 16) & 0xFF) as f32 / 255.0,
        g: ((hex >> 8) & 0xFF) as f32 / 255.0,
        b: (hex & 0xFF) as f32 / 255.0,
        a,
    }
}

fn mix(a: D2D1_COLOR_F, b: D2D1_COLOR_F, t: f32) -> D2D1_COLOR_F {
    D2D1_COLOR_F {
        r: a.r + (b.r - a.r) * t,
        g: a.g + (b.g - a.g) * t,
        b: a.b + (b.b - a.b) * t,
        a: a.a + (b.a - a.a) * t,
    }
}

// Palette: space gray, green, white.
const BG_TOP: u32 = 0x24262B;
const BG_BOTTOM: u32 = 0x17181B;
const CARD: u32 = 0x26282D;
const LINE: u32 = 0x33363D;
const TEXT: u32 = 0xF4F5F7;
const MUTED: u32 = 0x8E939B;
const GREEN: u32 = 0x3DDC84;
const GREEN_HI: u32 = 0x4BE597;
const GREEN_LO: u32 = 0x1FAE60;
const AMBER: u32 = 0xF2C14E;
const RED: u32 = 0xFF6B6B;

fn rect(l: f32, t: f32, r: f32, b: f32) -> D2D_RECT_F {
    D2D_RECT_F {
        left: l,
        top: t,
        right: r,
        bottom: b,
    }
}

fn v(x: f32, y: f32) -> Vector2 {
    Vector2 { X: x, Y: y }
}

fn ellipse(x: f32, y: f32, r: f32) -> D2D1_ELLIPSE {
    D2D1_ELLIPSE {
        point: v(x, y),
        radiusX: r,
        radiusY: r,
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hit {
    None,
    Power,
    Min,
    Close,
}

struct Gfx {
    d2d: ID2D1Factory,
    rt: Option<ID2D1HwndRenderTarget>,
    dw: IDWriteFactory,
    brand: IDWriteTextFormat,
    sub: IDWriteTextFormat,
    status: IDWriteTextFormat,
    name: IDWriteTextFormat,
    small: IDWriteTextFormat,
    round: ID2D1StrokeStyle,
}

struct Ui {
    gfx: Option<Gfx>,
    hover: Hit,
    pressed: Hit,
    tracking: bool,
    /// 0 = off look, 1 = on look; eased toward the target by the timer.
    t: f32,
    spin: f32,
    last_tick: Instant,
    timer: bool,
    tray_icons: [HICON; 2],
    tray_added: bool,
    told_tray: bool,
    taskbar_created: u32,
}

thread_local! {
    static UI: RefCell<Ui> = RefCell::new(Ui {
        gfx: None,
        hover: Hit::None,
        pressed: Hit::None,
        tracking: false,
        t: 0.0,
        spin: 0.0,
        last_tick: Instant::now(),
        timer: false,
        tray_icons: [HICON::default(); 2],
        tray_added: false,
        told_tray: false,
        taskbar_created: 0,
    });
}

fn font_family(dw: &IDWriteFactory) -> &'static str {
    // SAFETY: plain DirectWrite queries.
    unsafe {
        let mut coll = None;
        if dw.GetSystemFontCollection(&mut coll, false).is_ok()
            && let Some(c) = coll
        {
            let mut idx = 0;
            let mut exists = false.into();
            if c.FindFamilyName(w!("Segoe UI Variable Display"), &mut idx, &mut exists)
                .is_ok()
                && exists.as_bool()
            {
                return "Segoe UI Variable Display";
            }
        }
    }
    "Segoe UI"
}

impl Gfx {
    fn new() -> windows::core::Result<Self> {
        // SAFETY: factory creation and plain COM calls.
        unsafe {
            let d2d: ID2D1Factory = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, None)?;
            let dw: IDWriteFactory = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED)?;
            let fam = HSTRING::from(font_family(&dw));
            let fmt = |size: f32,
                       weight: DWRITE_FONT_WEIGHT,
                       center: bool|
             -> windows::core::Result<IDWriteTextFormat> {
                let f = dw.CreateTextFormat(
                    &fam,
                    None,
                    weight,
                    DWRITE_FONT_STYLE_NORMAL,
                    DWRITE_FONT_STRETCH_NORMAL,
                    size,
                    w!("en-us"),
                )?;
                f.SetTextAlignment(if center {
                    DWRITE_TEXT_ALIGNMENT_CENTER
                } else {
                    DWRITE_TEXT_ALIGNMENT_LEADING
                })?;
                f.SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER)?;
                f.SetWordWrapping(DWRITE_WORD_WRAPPING_WRAP)?;
                Ok(f)
            };
            let round = d2d.CreateStrokeStyle(
                &D2D1_STROKE_STYLE_PROPERTIES {
                    startCap: D2D1_CAP_STYLE_ROUND,
                    endCap: D2D1_CAP_STYLE_ROUND,
                    dashCap: D2D1_CAP_STYLE_ROUND,
                    lineJoin: D2D1_LINE_JOIN_ROUND,
                    miterLimit: 10.0,
                    dashStyle: D2D1_DASH_STYLE_SOLID,
                    dashOffset: 0.0,
                },
                None,
            )?;
            Ok(Self {
                brand: fmt(30.0, DWRITE_FONT_WEIGHT_SEMI_BOLD, true)?,
                sub: fmt(13.0, DWRITE_FONT_WEIGHT_NORMAL, true)?,
                status: fmt(20.0, DWRITE_FONT_WEIGHT_SEMI_BOLD, true)?,
                name: fmt(14.5, DWRITE_FONT_WEIGHT_SEMI_BOLD, false)?,
                small: fmt(11.5, DWRITE_FONT_WEIGHT_NORMAL, false)?,
                d2d,
                rt: None,
                dw,
                round,
            })
        }
    }

    fn target(&mut self, hwnd: HWND) -> windows::core::Result<ID2D1HwndRenderTarget> {
        if let Some(rt) = &self.rt {
            return Ok(rt.clone());
        }
        // SAFETY: plain Win32/D2D calls on our window.
        unsafe {
            let mut rc = RECT::default();
            GetClientRect(hwnd, &mut rc)?;
            let dpi = GetDpiForWindow(hwnd) as f32;
            let rt = self.d2d.CreateHwndRenderTarget(
                &D2D1_RENDER_TARGET_PROPERTIES {
                    // CPU rendering: the GPU driver alone costs ~50 MB of RAM, this UI needs none of it.
                    r#type: D2D1_RENDER_TARGET_TYPE_SOFTWARE,
                    pixelFormat: D2D1_PIXEL_FORMAT {
                        format: DXGI_FORMAT_UNKNOWN,
                        alphaMode: D2D1_ALPHA_MODE_UNKNOWN,
                    },
                    dpiX: dpi,
                    dpiY: dpi,
                    usage: D2D1_RENDER_TARGET_USAGE_NONE,
                    minLevel: D2D1_FEATURE_LEVEL_DEFAULT,
                },
                &D2D1_HWND_RENDER_TARGET_PROPERTIES {
                    hwnd,
                    pixelSize: D2D_SIZE_U {
                        width: (rc.right - rc.left) as u32,
                        height: (rc.bottom - rc.top) as u32,
                    },
                    presentOptions: D2D1_PRESENT_OPTIONS_NONE,
                },
            )?;
            rt.SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);
            self.rt = Some(rt.clone());
            Ok(rt)
        }
    }
}

fn dpi_scale(hwnd: HWND) -> f32 {
    // SAFETY: plain query.
    unsafe { GetDpiForWindow(hwnd) as f32 / 96.0 }
}

/// Mouse position in DIPs from an lParam in client pixels.
fn dip_point(hwnd: HWND, lp: LPARAM) -> (f32, f32) {
    let s = dpi_scale(hwnd);
    let x = (lp.0 & 0xFFFF) as i16 as f32;
    let y = ((lp.0 >> 16) & 0xFFFF) as i16 as f32;
    (x / s, y / s)
}

fn hit(x: f32, y: f32) -> Hit {
    if y < BAR {
        if x >= W - 46.0 {
            return Hit::Close;
        }
        if x >= W - 92.0 {
            return Hit::Min;
        }
        return Hit::None;
    }
    let (dx, dy) = (x - C.0, y - C.1);
    if dx * dx + dy * dy <= (R_BTN + 6.0) * (R_BTN + 6.0) {
        return Hit::Power;
    }
    Hit::None
}

fn svc_text(s: Svc, opened: usize) -> (String, u32) {
    match s {
        Svc::Off => ("Off".into(), MUTED),
        Svc::Checking => ("Checking the connection…".into(), AMBER),
        Svc::Open(_) if opened == 1 => ("1 blocked site opened".into(), GREEN),
        Svc::Open(_) if opened > 1 => (format!("{opened} blocked sites opened"), GREEN),
        Svc::Open(ms) => (format!("Ready · {ms} ms"), GREEN),
        Svc::Blocked => ("Not getting through on this network".into(), RED),
    }
}

unsafe fn paint(hwnd: HWND, ui: &mut Ui) -> windows::core::Result<()> {
    let Some(g) = ui.gfx.as_mut() else {
        return Ok(());
    };
    let rt = g.target(hwnd)?;
    let (power, error, check) = {
        let m = app::MODEL.lock().unwrap();
        (m.power, m.error.clone(), m.check)
    };
    let opened = app::opened();
    let t = ui.t;
    let busy = matches!(power, Power::Starting | Power::Stopping);
    // SAFETY: drawing calls between BeginDraw and EndDraw on our render target.
    unsafe {
        rt.BeginDraw();
        rt.SetTransform(&Matrix3x2::identity());
        let brush = |c: D2D1_COLOR_F| rt.CreateSolidColorBrush(&c, None);
        let stops = |s: &[(f32, D2D1_COLOR_F)]| {
            let v: Vec<D2D1_GRADIENT_STOP> = s
                .iter()
                .map(|(p, c)| D2D1_GRADIENT_STOP {
                    position: *p,
                    color: *c,
                })
                .collect();
            rt.CreateGradientStopCollection(&v, D2D1_GAMMA_2_2, D2D1_EXTEND_MODE_CLAMP)
        };

        // background
        let bg = rt.CreateLinearGradientBrush(
            &D2D1_LINEAR_GRADIENT_BRUSH_PROPERTIES {
                startPoint: v(0.0, 0.0),
                endPoint: v(0.0, H),
            },
            None,
            &stops(&[(0.0, rgb(BG_TOP, 1.0)), (1.0, rgb(BG_BOTTOM, 1.0))])?,
        )?;
        rt.FillRectangle(&rect(0.0, 0.0, W + 2.0, H + 2.0), &bg);

        // window buttons
        let muted = brush(rgb(MUTED, 1.0))?;
        let white = brush(rgb(TEXT, 1.0))?;
        if ui.hover == Hit::Min {
            rt.FillRectangle(
                &rect(W - 92.0, 0.0, W - 46.0, BAR),
                &brush(rgb(0xFFFFFF, 0.06))?,
            );
        }
        if ui.hover == Hit::Close {
            rt.FillRectangle(&rect(W - 46.0, 0.0, W, BAR), &brush(rgb(0xC42B1C, 1.0))?);
        }
        let mb = if ui.hover == Hit::Min { &white } else { &muted };
        rt.DrawLine(v(W - 74.0, 20.0), v(W - 64.0, 20.0), mb, 1.2, None);
        let cb = if ui.hover == Hit::Close {
            &white
        } else {
            &muted
        };
        rt.DrawLine(v(W - 28.0, 15.0), v(W - 18.0, 25.0), cb, 1.2, None);
        rt.DrawLine(v(W - 28.0, 25.0), v(W - 18.0, 15.0), cb, 1.2, None);

        // brand: "Ez" white, "Pi" green
        let text = wide("EzPi");
        let layout = g.dw.CreateTextLayout(&text, &g.brand, W, 44.0)?;
        let green = brush(rgb(GREEN, 1.0))?;
        layout.SetDrawingEffect(
            &green.cast::<windows::core::IUnknown>()?,
            DWRITE_TEXT_RANGE {
                startPosition: 2,
                length: 2,
            },
        )?;
        rt.DrawTextLayout(v(0.0, 50.0), &layout, &white, D2D1_DRAW_TEXT_OPTIONS_NONE);
        rt.DrawText(
            &wide("Unblock sites and apps without a VPN"),
            &g.sub,
            &rect(0.0, 94.0, W, 114.0),
            &muted,
            D2D1_DRAW_TEXT_OPTIONS_NONE,
            DWRITE_MEASURING_MODE_NATURAL,
        );

        // glow
        if t > 0.01 {
            let glow = rt.CreateRadialGradientBrush(
                &D2D1_RADIAL_GRADIENT_BRUSH_PROPERTIES {
                    center: v(C.0, C.1),
                    gradientOriginOffset: v(0.0, 0.0),
                    radiusX: 132.0,
                    radiusY: 132.0,
                },
                None,
                &stops(&[
                    (0.5, rgb(GREEN, 0.30 * t)),
                    (0.75, rgb(GREEN, 0.08 * t)),
                    (1.0, rgb(GREEN, 0.0)),
                ])?,
            )?;
            rt.FillEllipse(&ellipse(C.0, C.1, 132.0), &glow);
        }
        // outer ring
        let ring = brush(mix(rgb(LINE, 1.0), rgb(GREEN, 0.55), t))?;
        rt.DrawEllipse(&ellipse(C.0, C.1, R_BTN + 12.0), &ring, 1.5, None);
        // button: off face, then the green face on top with opacity t
        let off_face = rt.CreateRadialGradientBrush(
            &D2D1_RADIAL_GRADIENT_BRUSH_PROPERTIES {
                center: v(C.0, C.1 - 30.0),
                gradientOriginOffset: v(0.0, 0.0),
                radiusX: R_BTN * 1.5,
                radiusY: R_BTN * 1.5,
            },
            None,
            &stops(&[(0.0, rgb(0x3A3D44, 1.0)), (1.0, rgb(0x232529, 1.0))])?,
        )?;
        rt.FillEllipse(&ellipse(C.0, C.1, R_BTN), &off_face);
        if t > 0.01 {
            let on_face = rt.CreateLinearGradientBrush(
                &D2D1_LINEAR_GRADIENT_BRUSH_PROPERTIES {
                    startPoint: v(C.0, C.1 - R_BTN),
                    endPoint: v(C.0, C.1 + R_BTN),
                },
                None,
                &stops(&[(0.0, rgb(GREEN_HI, 1.0)), (1.0, rgb(GREEN_LO, 1.0))])?,
            )?;
            on_face.SetOpacity(t);
            rt.FillEllipse(&ellipse(C.0, C.1, R_BTN), &on_face);
        }
        // a thin top highlight gives the face some depth
        rt.DrawEllipse(
            &ellipse(C.0, C.1, R_BTN - 0.75),
            &brush(rgb(0xFFFFFF, 0.07 + 0.08 * t))?,
            1.5,
            None,
        );
        if ui.hover == Hit::Power || ui.pressed == Hit::Power {
            let a = if ui.pressed == Hit::Power { 0.10 } else { 0.05 };
            rt.FillEllipse(&ellipse(C.0, C.1, R_BTN), &brush(rgb(0xFFFFFF, a))?);
        }
        // power glyph
        let icon = brush(mix(rgb(0xA7ACB4, 1.0), rgb(0xFFFFFF, 1.0), t))?;
        let arc = g.d2d.CreatePathGeometry()?;
        let sink = arc.Open()?;
        let r = 25.0;
        let gap = 40f32.to_radians();
        sink.BeginFigure(
            v(C.0 + r * gap.sin(), C.1 - r * gap.cos()),
            D2D1_FIGURE_BEGIN_HOLLOW,
        );
        sink.AddArc(&D2D1_ARC_SEGMENT {
            point: v(C.0 - r * gap.sin(), C.1 - r * gap.cos()),
            size: D2D_SIZE_F {
                width: r,
                height: r,
            },
            rotationAngle: 0.0,
            sweepDirection: D2D1_SWEEP_DIRECTION_CLOCKWISE,
            arcSize: D2D1_ARC_SIZE_LARGE,
        });
        sink.EndFigure(D2D1_FIGURE_END_OPEN);
        sink.Close()?;
        rt.DrawGeometry(&arc, &icon, 6.0, &g.round);
        rt.DrawLine(v(C.0, C.1 - 34.0), v(C.0, C.1 - 8.0), &icon, 6.0, &g.round);

        // spinner while starting / stopping
        if busy {
            let sp = g.d2d.CreatePathGeometry()?;
            let s = sp.Open()?;
            let rr = R_BTN + 12.0;
            let a0 = ui.spin;
            let a1 = a0 + 75f32.to_radians();
            s.BeginFigure(
                v(C.0 + rr * a0.cos(), C.1 + rr * a0.sin()),
                D2D1_FIGURE_BEGIN_HOLLOW,
            );
            s.AddArc(&D2D1_ARC_SEGMENT {
                point: v(C.0 + rr * a1.cos(), C.1 + rr * a1.sin()),
                size: D2D_SIZE_F {
                    width: rr,
                    height: rr,
                },
                rotationAngle: 0.0,
                sweepDirection: D2D1_SWEEP_DIRECTION_CLOCKWISE,
                arcSize: D2D1_ARC_SIZE_SMALL,
            });
            s.EndFigure(D2D1_FIGURE_END_OPEN);
            s.Close()?;
            rt.DrawGeometry(&sp, &green, 3.0, &g.round);
        }

        // status
        let (title, tcol) = match power {
            Power::Off => ("Not connected", TEXT),
            Power::Starting => ("Connecting…", TEXT),
            Power::On => ("Connected", GREEN),
            Power::Stopping => ("Disconnecting…", TEXT),
        };
        rt.DrawText(
            &wide(title),
            &g.status,
            &rect(0.0, 334.0, W, 362.0),
            &brush(rgb(tcol, 1.0))?,
            D2D1_DRAW_TEXT_OPTIONS_NONE,
            DWRITE_MEASURING_MODE_NATURAL,
        );
        let (line, lcol) = match (&error, power) {
            (Some(e), _) => (e.clone(), RED),
            (None, Power::Off) => ("Tap the button to unblock every site".into(), MUTED),
            (None, Power::Starting) => ("Setting things up".into(), MUTED),
            (None, Power::On) => ("Blocked sites and apps open normally".into(), MUTED),
            (None, Power::Stopping) => ("Putting things back".into(), MUTED),
        };
        rt.DrawText(
            &wide(&line),
            &g.sub,
            &rect(24.0, 360.0, W - 24.0, 396.0),
            &brush(rgb(lcol, 1.0))?,
            D2D1_DRAW_TEXT_OPTIONS_NONE,
            DWRITE_MEASURING_MODE_NATURAL,
        );

        // service cards
        {
            let (label, s) = ("All sites and apps", check);
            let x = 24.0;
            let y = 408.0;
            let card = D2D1_ROUNDED_RECT {
                rect: rect(x, y, W - 24.0, y + 56.0),
                radiusX: 14.0,
                radiusY: 14.0,
            };
            rt.FillRoundedRectangle(&card, &brush(rgb(CARD, 1.0))?);
            rt.DrawRoundedRectangle(&card, &brush(rgb(LINE, 1.0))?, 1.0, None);
            let (detail, dcol) = svc_text(s, opened);
            let (cx, cy) = (x + 22.0, y + 28.0);
            match s {
                Svc::Off => rt.DrawEllipse(
                    &ellipse(cx, cy, 8.0),
                    &brush(rgb(0x4A4E55, 1.0))?,
                    1.5,
                    None,
                ),
                Svc::Checking => rt.FillEllipse(&ellipse(cx, cy, 5.0), &brush(rgb(AMBER, 1.0))?),
                Svc::Open(_) => {
                    rt.FillEllipse(&ellipse(cx, cy, 9.0), &green);
                    let k = brush(rgb(0x14361F, 1.0))?;
                    rt.DrawLine(
                        v(cx - 4.0, cy + 0.2),
                        v(cx - 1.2, cy + 3.0),
                        &k,
                        2.0,
                        &g.round,
                    );
                    rt.DrawLine(
                        v(cx - 1.2, cy + 3.0),
                        v(cx + 4.2, cy - 3.0),
                        &k,
                        2.0,
                        &g.round,
                    );
                }
                Svc::Blocked => {
                    rt.FillEllipse(&ellipse(cx, cy, 9.0), &brush(rgb(RED, 1.0))?);
                    let k = brush(rgb(0x3A1414, 1.0))?;
                    rt.DrawLine(
                        v(cx - 3.0, cy - 3.0),
                        v(cx + 3.0, cy + 3.0),
                        &k,
                        2.0,
                        &g.round,
                    );
                    rt.DrawLine(
                        v(cx - 3.0, cy + 3.0),
                        v(cx + 3.0, cy - 3.0),
                        &k,
                        2.0,
                        &g.round,
                    );
                }
            }
            rt.DrawText(
                &wide(label),
                &g.name,
                &rect(x + 40.0, y + 8.0, W - 36.0, y + 30.0),
                &white,
                D2D1_DRAW_TEXT_OPTIONS_NONE,
                DWRITE_MEASURING_MODE_NATURAL,
            );
            rt.DrawText(
                &wide(&detail),
                &g.small,
                &rect(x + 40.0, y + 28.0, W - 36.0, y + 48.0),
                &brush(rgb(dcol, if dcol == MUTED { 1.0 } else { 0.9 }))?,
                D2D1_DRAW_TEXT_OPTIONS_NONE,
                DWRITE_MEASURING_MODE_NATURAL,
            );
        }

        // footer
        let mut foot = g.small.clone();
        foot = {
            let f = foot;
            f.SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER)?;
            f
        };
        rt.DrawText(
            &wide(concat!(
                "v",
                env!("CARGO_PKG_VERSION"),
                "  ·  Closing keeps it running in the tray"
            )),
            &foot,
            &rect(0.0, 472.0, W, 492.0),
            &brush(rgb(MUTED, 0.75))?,
            D2D1_DRAW_TEXT_OPTIONS_NONE,
            DWRITE_MEASURING_MODE_NATURAL,
        );
        foot.SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING)?;

        match rt.EndDraw(None, None) {
            Err(e) if e.code() == D2DERR_RECREATE_TARGET => g.rt = None,
            r => r?,
        }
    }
    Ok(())
}

fn small_icon(on: bool) -> HICON {
    // SAFETY: GDI calls creating a 32-bit icon from our pixels; the temporary bitmaps are deleted
    // after CreateIconIndirect copied them.
    unsafe {
        let size = GetSystemMetrics(SM_CXSMICON).max(16) as u32;
        let px = crate::art::badge(size, on);
        let bi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: size as i32,
                biHeight: -(size as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits = std::ptr::null_mut();
        let Ok(color) = CreateDIBSection(None, &bi, DIB_RGB_COLORS, &mut bits, None, 0) else {
            return HICON::default();
        };
        std::ptr::copy_nonoverlapping(px.as_ptr(), bits.cast::<u8>(), px.len());
        let mask = CreateBitmap(size as i32, size as i32, 1, 1, None);
        let info = ICONINFO {
            fIcon: true.into(),
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask,
            hbmColor: color,
        };
        let icon = CreateIconIndirect(&info).unwrap_or_default();
        let _ = DeleteObject(color.into());
        let _ = DeleteObject(mask.into());
        icon
    }
}

fn tray_data(hwnd: HWND, icon: HICON, tip: &str) -> NOTIFYICONDATAW {
    let mut d = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
        uCallbackMessage: WM_TRAY,
        hIcon: icon,
        ..Default::default()
    };
    for (i, c) in tip.encode_utf16().take(127).enumerate() {
        d.szTip[i] = c;
    }
    d
}

fn sync_tray(hwnd: HWND, ui: &mut Ui) {
    let on = app::power() == Power::On;
    let tip = if on {
        "EzPi: connected"
    } else {
        "EzPi: not connected"
    };
    let d = tray_data(hwnd, ui.tray_icons[usize::from(on)], tip);
    // SAFETY: a fully initialised NOTIFYICONDATAW for our window.
    unsafe {
        if ui.tray_added {
            let _ = Shell_NotifyIconW(NIM_MODIFY, &d);
        } else {
            ui.tray_added = Shell_NotifyIconW(NIM_ADD, &d).as_bool();
        }
    }
}

fn tray_note(hwnd: HWND, title: &str, text: &str) {
    let mut d = tray_data(hwnd, HICON::default(), "");
    d.uFlags = NIF_INFO;
    for (i, c) in title.encode_utf16().take(63).enumerate() {
        d.szInfoTitle[i] = c;
    }
    for (i, c) in text.encode_utf16().take(255).enumerate() {
        d.szInfo[i] = c;
    }
    // SAFETY: as above.
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &d);
    }
}

fn show(hwnd: HWND) {
    // SAFETY: plain window calls.
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = ShowWindow(hwnd, SW_RESTORE);
        let _ = SetForegroundWindow(hwnd);
    }
}

/// Hide to the tray and give the drawing memory back: nothing is drawn while hidden.
fn hide(hwnd: HWND, ui: &mut Ui) {
    // SAFETY: plain window/process calls.
    unsafe {
        let _ = ShowWindow(hwnd, SW_HIDE);
        if let Some(g) = ui.gfx.as_mut() {
            g.rt = None;
        }
        let _ = windows::Win32::System::Threading::SetProcessWorkingSetSize(
            windows::Win32::System::Threading::GetCurrentProcess(),
            usize::MAX,
            usize::MAX,
        );
    }
}

fn close(hwnd: HWND, ui: &mut Ui) {
    if matches!(app::power(), Power::On | Power::Starting) {
        hide(hwnd, ui);
        if !ui.told_tray {
            ui.told_tray = true;
            tray_note(
                hwnd,
                "EzPi is still on",
                "It keeps working in the background. Click the tray icon to open it.",
            );
        }
    } else {
        // SAFETY: plain window call.
        unsafe {
            let _ = DestroyWindow(hwnd);
        }
    }
}

fn menu(hwnd: HWND) {
    // SAFETY: a popup menu we create and destroy here.
    unsafe {
        let Ok(m) = CreatePopupMenu() else { return };
        let on = app::power() == Power::On;
        let _ = AppendMenuW(m, MF_STRING, CMD_OPEN, w!("Open EzPi"));
        let _ = AppendMenuW(
            m,
            MF_STRING,
            CMD_TOGGLE,
            if on { w!("Turn off") } else { w!("Turn on") },
        );
        let _ = AppendMenuW(m, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(m, MF_STRING, CMD_UNINSTALL, w!("Uninstall EzPi…"));
        let _ = AppendMenuW(m, MF_STRING, CMD_QUIT, w!("Quit"));
        let mut pt = POINT::default();
        let _ = GetCursorPos(&mut pt);
        let _ = SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(
            m,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            None,
            hwnd,
            None,
        );
        let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));
        let _ = DestroyMenu(m);
        match cmd.0 as usize {
            CMD_OPEN => show(hwnd),
            CMD_TOGGLE => app::toggle(),
            CMD_QUIT => {
                let _ = DestroyWindow(hwnd);
            }
            CMD_UNINSTALL => {
                let r = MessageBoxW(
                    Some(hwnd),
                    w!("Remove EzPi from this PC? Everything it changed is put back."),
                    w!("EzPi"),
                    MB_YESNO | MB_ICONQUESTION,
                );
                if r == IDYES {
                    app::shutdown();
                    crate::install::uninstall();
                    let _ = DestroyWindow(hwnd);
                }
            }
            _ => {}
        }
    }
}

fn ensure_timer(hwnd: HWND, ui: &mut Ui) {
    if !ui.timer {
        ui.timer = true;
        ui.last_tick = Instant::now();
        // SAFETY: plain timer on our window.
        unsafe {
            SetTimer(Some(hwnd), TIMER, 16, None);
        }
    }
}

fn invalidate(hwnd: HWND) {
    // SAFETY: plain call.
    unsafe {
        let _ = InvalidateRect(Some(hwnd), None, false);
    }
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // DestroyWindow is called from inside our own handlers (close, Quit, Uninstall), so
    // WM_DESTROY arrives while `UI` is borrowed: handle it without touching `UI`, or the
    // message loop never ends and a windowless EzPi stays running.
    if msg == WM_DESTROY {
        let d = tray_data(hwnd, HICON::default(), "");
        // SAFETY: removing our own tray icon and ending our message loop.
        unsafe {
            let _ = Shell_NotifyIconW(NIM_DELETE, &d);
            app::shutdown();
            PostQuitMessage(0);
        }
        return LRESULT(0);
    }
    UI.with(|cell| {
        let Ok(mut ui) = cell.try_borrow_mut() else {
            // SAFETY: re-entrant message during one of ours (e.g. from DestroyWindow).
            return unsafe { DefWindowProcW(hwnd, msg, wp, lp) };
        };
        handle(hwnd, msg, wp, lp, &mut ui)
    })
}

fn handle(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM, ui: &mut Ui) -> LRESULT {
    // SAFETY: standard window-procedure work on our own window.
    unsafe {
        match msg {
            WM_NCCALCSIZE if wp.0 != 0 => return LRESULT(0),
            WM_NCHITTEST => {
                let mut pt = POINT {
                    x: (lp.0 & 0xFFFF) as i16 as i32,
                    y: ((lp.0 >> 16) & 0xFFFF) as i16 as i32,
                };
                let _ = ScreenToClient(hwnd, &mut pt);
                let s = dpi_scale(hwnd);
                let (x, y) = (pt.x as f32 / s, pt.y as f32 / s);
                if y < BAR && x < W - 92.0 {
                    return LRESULT(HTCAPTION as isize);
                }
                return LRESULT(HTCLIENT as isize);
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                BeginPaint(hwnd, &mut ps);
                if let Err(e) = paint(hwnd, ui) {
                    crate::log::line(&format!("paint: {e}"));
                }
                let _ = EndPaint(hwnd, &ps);
                return LRESULT(0);
            }
            WM_ERASEBKGND => return LRESULT(1),
            WM_SIZE => {
                if let Some(rt) = ui.gfx.as_ref().and_then(|g| g.rt.as_ref()) {
                    let _ = rt.Resize(&D2D_SIZE_U {
                        width: (lp.0 & 0xFFFF) as u32,
                        height: ((lp.0 >> 16) & 0xFFFF) as u32,
                    });
                }
                return LRESULT(0);
            }
            WM_DPICHANGED => {
                let r = &*(lp.0 as *const RECT);
                let _ = SetWindowPos(
                    hwnd,
                    None,
                    r.left,
                    r.top,
                    r.right - r.left,
                    r.bottom - r.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
                if let Some(rt) = ui.gfx.as_ref().and_then(|g| g.rt.as_ref()) {
                    let d = (wp.0 & 0xFFFF) as f32;
                    rt.SetDpi(d, d);
                }
                invalidate(hwnd);
                return LRESULT(0);
            }
            WM_MOUSEMOVE => {
                let (x, y) = dip_point(hwnd, lp);
                let h = hit(x, y);
                if !ui.tracking {
                    let mut tme = TRACKMOUSEEVENT {
                        cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    let _ = TrackMouseEvent(&mut tme);
                    ui.tracking = true;
                }
                if h != ui.hover {
                    ui.hover = h;
                    invalidate(hwnd);
                }
                return LRESULT(0);
            }
            WM_MOUSELEAVE => {
                ui.tracking = false;
                if ui.hover != Hit::None || ui.pressed != Hit::None {
                    ui.hover = Hit::None;
                    ui.pressed = Hit::None;
                    invalidate(hwnd);
                }
                return LRESULT(0);
            }
            WM_SETCURSOR => {
                if ui.hover != Hit::None && (lp.0 & 0xFFFF) as u32 == HTCLIENT {
                    if let Ok(c) = LoadCursorW(None, IDC_HAND) {
                        SetCursor(Some(c));
                    }
                    return LRESULT(1);
                }
            }
            WM_LBUTTONDOWN => {
                let (x, y) = dip_point(hwnd, lp);
                ui.pressed = hit(x, y);
                SetCapture(hwnd);
                invalidate(hwnd);
                return LRESULT(0);
            }
            WM_LBUTTONUP => {
                let _ = ReleaseCapture();
                let (x, y) = dip_point(hwnd, lp);
                let h = hit(x, y);
                let pressed = std::mem::replace(&mut ui.pressed, Hit::None);
                invalidate(hwnd);
                if h == pressed {
                    match h {
                        Hit::Power => app::toggle(),
                        Hit::Min => {
                            let _ = ShowWindow(hwnd, SW_MINIMIZE);
                        }
                        Hit::Close => close(hwnd, ui),
                        Hit::None => {}
                    }
                }
                return LRESULT(0);
            }
            WM_KEYDOWN => {
                match VIRTUAL_KEY(wp.0 as u16) {
                    VK_SPACE | VK_RETURN => app::toggle(),
                    VK_ESCAPE => close(hwnd, ui),
                    _ => {}
                }
                return LRESULT(0);
            }
            WM_CLOSE => {
                close(hwnd, ui);
                return LRESULT(0);
            }
            WM_TIMER if wp.0 == TIMER => {
                let now = Instant::now();
                let dt = now.duration_since(ui.last_tick).as_secs_f32().min(0.05);
                ui.last_tick = now;
                let power = app::power();
                let target = if matches!(power, Power::On | Power::Stopping) {
                    1.0
                } else {
                    0.0
                };
                let busy = matches!(power, Power::Starting | Power::Stopping);
                let step = dt / 0.22;
                if ui.t < target {
                    ui.t = (ui.t + step).min(target);
                } else if ui.t > target {
                    ui.t = (ui.t - step).max(target);
                }
                ui.spin = (ui.spin + dt * 5.5) % std::f32::consts::TAU;
                if !busy && (ui.t - target).abs() < f32::EPSILON {
                    let _ = KillTimer(Some(hwnd), TIMER);
                    ui.timer = false;
                }
                invalidate(hwnd);
                return LRESULT(0);
            }
            m if m == WM_MODEL => {
                sync_tray(hwnd, ui);
                ensure_timer(hwnd, ui);
                invalidate(hwnd);
                return LRESULT(0);
            }
            m if m == WM_SHOWME => {
                show(hwnd);
                return LRESULT(0);
            }
            m if m == WM_TRAY => {
                match (lp.0 & 0xFFFF) as u32 {
                    WM_LBUTTONUP => {
                        if IsWindowVisible(hwnd).as_bool() && !IsIconic(hwnd).as_bool() {
                            hide(hwnd, ui);
                        } else {
                            show(hwnd);
                        }
                    }
                    WM_RBUTTONUP | WM_CONTEXTMENU => menu(hwnd),
                    _ => {}
                }
                return LRESULT(0);
            }
            m if m == ui.taskbar_created && m != 0 => {
                ui.tray_added = false;
                sync_tray(hwnd, ui);
                return LRESULT(0);
            }
            WM_QUERYENDSESSION => return LRESULT(1),
            WM_ENDSESSION => {
                if wp.0 != 0 {
                    app::shutdown();
                }
                return LRESULT(0);
            }
            _ => {}
        }
        DefWindowProcW(hwnd, msg, wp, lp)
    }
}

/// Create the window and run the message loop until it is closed.
pub fn run() -> windows::core::Result<()> {
    // SAFETY: standard window setup and message loop on this thread.
    unsafe {
        let inst = GetModuleHandleW(None)?;
        let icon = LoadIconW(Some(inst.into()), PCWSTR(1 as _)).unwrap_or_default();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: inst.into(),
            hIcon: icon,
            hIconSm: icon,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            lpszClassName: CLASS,
            ..Default::default()
        };
        RegisterClassExW(&wc);
        UI.with(|c| {
            let mut ui = c.borrow_mut();
            ui.gfx = Gfx::new().ok();
            ui.tray_icons = [small_icon(false), small_icon(true)];
            ui.taskbar_created = RegisterWindowMessageW(w!("TaskbarCreated"));
        });
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            CLASS,
            w!("EzPi"),
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            0,
            0,
            100,
            100,
            None,
            None,
            Some(inst.into()),
            None,
        )?;
        app::set_window(hwnd);
        // A normal (not elevated) start of EzPi may ask this elevated window to come forward.
        let _ = ChangeWindowMessageFilterEx(hwnd, WM_SHOWME, MSGFLT_ALLOW, None);
        // Size for this monitor's DPI and centre in the work area.
        let s = dpi_scale(hwnd);
        let (w, h) = ((W * s).round() as i32, (H * s).round() as i32);
        let mut wa = RECT::default();
        let _ = SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some(std::ptr::from_mut(&mut wa).cast()),
            Default::default(),
        );
        let _ = SetWindowPos(
            hwnd,
            None,
            wa.left + (wa.right - wa.left - w) / 2,
            wa.top + (wa.bottom - wa.top - h) / 2,
            w,
            h,
            SWP_NOZORDER | SWP_FRAMECHANGED,
        );
        // Dark, rounded corners with the native shadow (Windows 11; ignored elsewhere).
        let set = |attr: DWMWINDOWATTRIBUTE, val: u32| {
            let _ = DwmSetWindowAttribute(hwnd, attr, std::ptr::from_ref(&val).cast(), 4);
        };
        set(DWMWA_USE_IMMERSIVE_DARK_MODE, 1);
        set(DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND.0 as u32);
        set(DWMWA_BORDER_COLOR, 0x003A3632);
        set(DWMWA_CAPTION_COLOR, 0x002B2624);
        let _ = DwmExtendFrameIntoClientArea(
            hwnd,
            &MARGINS {
                cxLeftWidth: 0,
                cxRightWidth: 0,
                cyTopHeight: 1,
                cyBottomHeight: 0,
            },
        );
        UI.with(|c| sync_tray(hwnd, &mut c.borrow_mut()));
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        // Release the drawing objects now, on this thread. Left to thread-local destructors they
        // are released during process exit, where Direct2D/DirectWrite can deadlock and keep a
        // windowless EzPi alive.
        UI.with(|c| {
            let mut ui = c.borrow_mut();
            ui.gfx = None;
            for i in std::mem::take(&mut ui.tray_icons) {
                if !i.is_invalid() {
                    let _ = DestroyIcon(i);
                }
            }
        });
    }
    Ok(())
}
