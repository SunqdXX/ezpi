// The EzPi mark (a power symbol on a round badge), rasterised with 4x4 supersampling. Plain
// std Rust: build.rs includes this file to write the exe's .ico, the app uses it for tray icons.

/// Straight-alpha BGRA pixels, top row first, `size` x `size`.
#[allow(dead_code)]
pub fn badge(size: u32, on: bool) -> Vec<u8> {
    let s = size as f32;
    let c = s / 2.0;
    let r_badge = s * 0.47;
    let r_arc = s * 0.215;
    let t = (s * 0.085).max(1.4);
    let gap = 38f32.to_radians(); // half-opening of the arc around 12 o'clock
    let bar_top = c - s * 0.31;
    let bar_bot = c - s * 0.05;
    let (top, bottom) = if on {
        ([0x8E, 0xE0, 0x43], [0x65, 0xB4, 0x22]) // BGR: #43E08E -> #22B465
    } else {
        ([0x4A, 0x46, 0x42], [0x34, 0x31, 0x2E]) // space gray
    };
    let glyph = [0xFF, 0xFF, 0xFF];
    let mut out = vec![0u8; (size * size * 4) as usize];
    const N: usize = 4;
    for y in 0..size {
        for x in 0..size {
            let (mut cov_badge, mut cov_glyph) = (0f32, 0f32);
            for sy in 0..N {
                for sx in 0..N {
                    let px = x as f32 + (sx as f32 + 0.5) / N as f32 - c;
                    let py = y as f32 + (sy as f32 + 0.5) / N as f32 - c;
                    let d = (px * px + py * py).sqrt();
                    if d > r_badge {
                        continue;
                    }
                    cov_badge += 1.0;
                    // arc: ring of width t, open at the top
                    let ang = px.atan2(-py).abs(); // 0 at 12 o'clock
                    let on_arc = (d - r_arc).abs() <= t / 2.0 && ang >= gap;
                    // round end caps of the arc
                    let cap = |a: f32| {
                        let (ex, ey) = (r_arc * a.sin(), -r_arc * a.cos());
                        let (dx, dy) = (px - ex, py - ey);
                        dx * dx + dy * dy <= (t / 2.0) * (t / 2.0)
                    };
                    // the bar: a capsule from bar_top to bar_bot
                    let yy = (py + c).clamp(bar_top, bar_bot) - c;
                    let on_bar = (px * px + (py - yy) * (py - yy)).sqrt() <= t / 2.0;
                    if on_arc || cap(gap) || cap(-gap) || on_bar {
                        cov_glyph += 1.0;
                    }
                }
            }
            let nn = (N * N) as f32;
            let (ab, ag) = (cov_badge / nn, cov_glyph / nn);
            if ab <= 0.0 {
                continue;
            }
            let k = y as f32 / s;
            let mut px = [0f32; 3];
            for i in 0..3 {
                let bg = top[i] as f32 * (1.0 - k) + bottom[i] as f32 * k;
                let g = ag / ab; // glyph share of the covered area
                px[i] = bg * (1.0 - g) + glyph[i] as f32 * g;
            }
            let o = ((y * size + x) * 4) as usize;
            out[o] = px[0] as u8;
            out[o + 1] = px[1] as u8;
            out[o + 2] = px[2] as u8;
            out[o + 3] = (ab * 255.0).round() as u8;
        }
    }
    out
}

/// An .ico file holding `sizes` (32-bit BMP entries).
#[allow(dead_code)]
pub fn ico(sizes: &[u32], on: bool) -> Vec<u8> {
    let mut images = Vec::new();
    for &sz in sizes {
        let px = badge(sz, on);
        let mut b = Vec::new();
        // BITMAPINFOHEADER, height doubled (XOR + AND masks)
        b.extend(40u32.to_le_bytes());
        b.extend((sz as i32).to_le_bytes());
        b.extend((sz as i32 * 2).to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(32u16.to_le_bytes());
        b.extend([0u8; 24]);
        for y in (0..sz).rev() {
            let row = (y * sz * 4) as usize;
            b.extend(&px[row..row + (sz * 4) as usize]);
        }
        let mask_row = sz.div_ceil(32) * 4;
        b.extend(vec![0u8; (mask_row * sz) as usize]);
        images.push((sz, b));
    }
    let mut out = Vec::new();
    out.extend([0u8, 0, 1, 0]);
    out.extend((images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (sz, b) in &images {
        let d = if *sz >= 256 { 0 } else { *sz as u8 };
        out.extend([d, d, 0, 0]);
        out.extend(1u16.to_le_bytes());
        out.extend(32u16.to_le_bytes());
        out.extend((b.len() as u32).to_le_bytes());
        out.extend(offset.to_le_bytes());
        offset += b.len() as u32;
    }
    for (_, b) in images {
        out.extend(b);
    }
    out
}
