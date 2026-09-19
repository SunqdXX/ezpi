package com.ezpi

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.view.View
import android.view.animation.DecelerateInterpolator

class RingView(context: Context) : View(context) {

    enum class State { OFF, CONNECTING, ON }

    private val green = 0xFF39D98A.toInt()
    private val offRing = 0xFF2E3138.toInt()
    private val glyphOff = 0xFF5E626B.toInt()

    private val density = resources.displayMetrics.density
    private fun dp(v: Float) = v * density

    private val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeWidth = dp(7f)
    }
    private val glyph = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeWidth = dp(6f)
    }

    private var glow = 1f
    private var anim: ValueAnimator? = null

    var state: State = State.OFF
        set(value) {
            if (field == value) return
            field = value
            startAnim()
            invalidate()
        }

    init {
        setLayerType(LAYER_TYPE_SOFTWARE, null) // the glow needs a software layer
    }

    private fun startAnim() {
        anim?.cancel()
        when (state) {
            State.CONNECTING -> anim = ValueAnimator.ofFloat(0f, 1f).apply {
                duration = 450
                interpolator = DecelerateInterpolator()
                addUpdateListener { glow = it.animatedValue as Float; invalidate() }
                start()
            }
            State.ON -> anim = ValueAnimator.ofFloat(0.6f, 1f).apply {
                duration = 1800; repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.REVERSE
                addUpdateListener { glow = it.animatedValue as Float; invalidate() }
                start()
            }
            State.OFF -> { anim = null; glow = 1f }
        }
    }

    override fun onDraw(canvas: Canvas) {
        val cx = width / 2f
        val cy = height / 2f
        val r = Math.min(width, height) / 2f - dp(22f)

        if (state == State.OFF) {
            ring.color = offRing
            ring.clearShadowLayer()
        } else {
            ring.color = green
            ring.setShadowLayer(dp(6f + 18f * glow), 0f, 0f, green)
        }
        canvas.drawCircle(cx, cy, r, ring)
        drawPower(canvas, cx, cy, r * 0.42f)
    }

    private fun drawPower(canvas: Canvas, cx: Float, cy: Float, gr: Float) {
        val on = state != State.OFF
        glyph.color = if (on) green else glyphOff
        if (on) glyph.setShadowLayer(dp(10f), 0f, 0f, green) else glyph.clearShadowLayer()
        val gbox = RectF(cx - gr, cy - gr, cx + gr, cy + gr)
        val path = Path()
        path.addArc(gbox, -65f, 310f)
        canvas.drawPath(path, glyph)
        canvas.drawLine(cx, cy - gr * 1.05f, cx, cy - gr * 0.15f, glyph)
    }
}
