import { useRef, useEffect, useCallback, useState } from 'react'

export default function Sparkline({ data, color, labels, width, height }) {
  const canvasRef = useRef(null)
  const baseRef = useRef(null)
  const layoutRef = useRef(null)
  const [hover, setHover] = useState(null)

  // Draw base chart and save snapshot + layout info
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !data || data.length < 2) return

    const dpr = window.devicePixelRatio || 1
    const w = width || canvas.parentElement.clientWidth
    const h = height || 160

    canvas.width = w * dpr
    canvas.height = h * dpr
    canvas.style.width = w + 'px'
    canvas.style.height = h + 'px'

    const ctx = canvas.getContext('2d')
    ctx.scale(dpr, dpr)
    ctx.clearRect(0, 0, w, h)

    const padTop = 20
    const padBottom = 28
    const padLeft = 50
    const padRight = 16
    const plotW = w - padLeft - padRight
    const plotH = h - padTop - padBottom

    const min = Math.min(...data)
    const max = Math.max(...data)
    const range = max - min || 1

    function xPos(i) {
      return padLeft + (i / (data.length - 1)) * plotW
    }
    function yPos(v) {
      return padTop + plotH - ((v - min) / range) * plotH
    }

    // Grid lines
    ctx.strokeStyle = '#f1f5f9'
    ctx.lineWidth = 1
    for (let i = 0; i <= 3; i++) {
      const y = padTop + (plotH / 3) * i
      ctx.beginPath()
      ctx.moveTo(padLeft, y)
      ctx.lineTo(w - padRight, y)
      ctx.stroke()
    }

    // Y-axis labels
    ctx.fillStyle = '#94a3b8'
    ctx.font = '11px -apple-system, sans-serif'
    ctx.textAlign = 'right'
    ctx.textBaseline = 'middle'
    for (let i = 0; i <= 3; i++) {
      const val = max - (range / 3) * i
      ctx.fillText(formatNum(val), padLeft - 8, padTop + (plotH / 3) * i)
    }

    // X-axis labels
    ctx.textAlign = 'center'
    ctx.textBaseline = 'top'
    const labelInterval = Math.max(1, Math.floor(data.length / 6))
    for (let i = 0; i < data.length; i += labelInterval) {
      ctx.fillText(labels ? labels[i] : '', xPos(i), padTop + plotH + 8)
    }
    if ((data.length - 1) % labelInterval !== 0) {
      ctx.fillText(labels ? labels[data.length - 1] : '', xPos(data.length - 1), padTop + plotH + 8)
    }

    // Area fill
    ctx.beginPath()
    ctx.moveTo(xPos(0), yPos(data[0]))
    for (let i = 1; i < data.length; i++) ctx.lineTo(xPos(i), yPos(data[i]))
    ctx.lineTo(xPos(data.length - 1), padTop + plotH)
    ctx.lineTo(xPos(0), padTop + plotH)
    ctx.closePath()
    const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH)
    grad.addColorStop(0, color + '20')
    grad.addColorStop(1, color + '05')
    ctx.fillStyle = grad
    ctx.fill()

    // Line
    ctx.beginPath()
    ctx.moveTo(xPos(0), yPos(data[0]))
    for (let i = 1; i < data.length; i++) ctx.lineTo(xPos(i), yPos(data[i]))
    ctx.strokeStyle = color
    ctx.lineWidth = 1.5
    ctx.lineJoin = 'round'
    ctx.stroke()

    // Last point dot + value
    const lastX = xPos(data.length - 1)
    const lastY = yPos(data[data.length - 1])
    ctx.beginPath()
    ctx.arc(lastX, lastY, 3, 0, Math.PI * 2)
    ctx.fillStyle = color
    ctx.fill()
    ctx.fillStyle = color
    ctx.font = '600 12px -apple-system, sans-serif'
    ctx.textAlign = 'left'
    ctx.textBaseline = 'bottom'
    ctx.fillText(formatNum(data[data.length - 1]), lastX + 6, lastY - 2)

    // Save base image and layout
    baseRef.current = ctx.getImageData(0, 0, canvas.width, canvas.height)
    layoutRef.current = { dpr, w, h, padLeft, padRight, plotW, plotH, min, range, padTop, dataLen: data.length }
  }, [data, color, labels, width, height])

  // Overlay hover indicator on top of saved base
  useEffect(() => {
    const canvas = canvasRef.current
    const base = baseRef.current
    const layout = layoutRef.current
    if (!canvas || !base || !layout || !data || data.length < 2) return

    const ctx = canvas.getContext('2d')
    const { dpr, w, padLeft, padRight, plotW, plotH, padTop, min, range } = layout

    ctx.putImageData(base, 0, 0)
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

    if (hover == null || hover < 0 || hover >= data.length) return

    function xPos(i) { return padLeft + (i / (data.length - 1)) * plotW }
    function yPos(v) { return padTop + plotH - ((v - min) / range) * plotH }

    const hx = xPos(hover)
    const hy = yPos(data[hover])

    // Dot
    ctx.beginPath()
    ctx.arc(hx, hy, 3, 0, Math.PI * 2)
    ctx.fillStyle = color
    ctx.fill()

    // Value label
    ctx.fillStyle = color
    ctx.font = '600 12px -apple-system, sans-serif'
    ctx.textAlign = hx > padLeft + plotW / 2 ? 'right' : 'left'
    ctx.textBaseline = 'bottom'
    ctx.fillText(formatNum(data[hover]), hx > padLeft + plotW / 2 ? hx - 6 : hx + 6, hy - 4)
  }, [hover, data, color])

  const handleMouseMove = useCallback((e) => {
    const layout = layoutRef.current
    if (!layout || !data || data.length < 2) return
    const canvas = canvasRef.current
    const rect = canvas.getBoundingClientRect()
    const mx = e.clientX - rect.left
    const { padLeft, padRight, plotW, w } = layout
    const ratio = (mx - padLeft) / plotW
    const idx = Math.round(ratio * (data.length - 1))
    setHover(idx >= 0 && idx < data.length ? idx : null)
  }, [data])

  const handleMouseLeave = useCallback(() => setHover(null), [])

  return <canvas ref={canvasRef} onMouseMove={handleMouseMove} onMouseLeave={handleMouseLeave} />
}

function formatNum(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K'
  return Math.round(n).toString()
}
