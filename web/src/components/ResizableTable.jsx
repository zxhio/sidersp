import { useState, useCallback, useRef, useEffect } from 'react'

/**
 * Column resize hook with zero-cost drag.
 *
 * During drag: only moves a 1px guide line, no table reflow.
 * On mouseup: commits final width to React state in one shot.
 *
 * All drag context is stored in a ref — no closure staleness issues.
 * Events are bound to window for reliable capture.
 */
export function useResizableColumns(initial) {
  const [overrides, setOverrides] = useState({})
  const initialRef = useRef(initial)
  initialRef.current = initial

  // Single ref holds all drag context
  const dragRef = useRef({
    active: false,
    key: null,
    startX: 0,
    startWidth: 0,
    guideEl: null,
  })

  useEffect(() => {
    // Create the guide line element once
    const guide = document.createElement('div')
    guide.style.cssText =
      'position:fixed;width:1px;background:#a0c4ff;pointer-events:none;z-index:200;display:none;'
    document.body.appendChild(guide)
    dragRef.current.guideEl = guide
    return () => guide.remove()
  }, [])

  // Stable handlers — read from ref, no closure capture issues
  useEffect(() => {
    function handleMouseMove(ev) {
      const d = dragRef.current
      if (!d.active) return
      d.guideEl.style.left = ev.clientX + 'px'
    }

    function handleMouseUp(ev) {
      const d = dragRef.current
      if (!d.active) return

      d.active = false
      d.guideEl.style.display = 'none'
      document.body.style.cursor = ''
      document.body.style.userSelect = ''

      const init = initialRef.current
      const delta = ev.clientX - d.startX
      const finalWidth = Math.max(init[d.key] || 40, d.startWidth + delta)
      const key = d.key
      setOverrides(prev => ({ ...prev, [key]: finalWidth }))
    }

    window.addEventListener('mousemove', handleMouseMove)
    window.addEventListener('mouseup', handleMouseUp)
    return () => {
      window.removeEventListener('mousemove', handleMouseMove)
      window.removeEventListener('mouseup', handleMouseUp)
    }
  }, [])

  const onResizeStart = useCallback((key, e) => {
    e.preventDefault()
    e.stopPropagation()

    const d = dragRef.current
    if (d.active) return // already dragging

    const th = e.currentTarget.closest('th')
    if (!th) return
    const startWidth = th.offsetWidth
    const tableRect = th.closest('table').getBoundingClientRect()
    const guideX = th.getBoundingClientRect().right

    d.active = true
    d.key = key
    d.startX = e.clientX
    d.startWidth = startWidth

    // Position guide line
    d.guideEl.style.display = 'block'
    d.guideEl.style.left = guideX + 'px'
    d.guideEl.style.top = tableRect.top + 'px'
    d.guideEl.style.height = tableRect.height + 'px'

    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }, [])

  function colStyle(key) {
    const min = initial[key] || 40
    if (overrides[key] != null) {
      return { width: overrides[key], minWidth: min }
    }
    return { minWidth: min }
  }

  return { colStyle, onResizeStart }
}
