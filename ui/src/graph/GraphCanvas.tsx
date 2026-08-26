/**
 * The code graph canvas.
 *
 * Pan with a drag on the background, zoom with the wheel or the buttons, and
 * "fit" re-frames the whole graph. The transform is the only state here — node
 * positions come from the pure layout module and are never touched, so the
 * picture is identical on every mount and a screenshot of it is reproducible.
 *
 * Three visual channels, kept independent so they can be read at the same time:
 *   shape/stroke  what the method IS      (entrypoint, intermediate, sink)
 *   fill          what was RETRIEVED      (hollow, decompiled, interpreted)
 *   opacity       what is currently in FOCUS (path filter, retrieval replay)
 */

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { Crosshair, Minus, Plus } from 'lucide-react'
import { NODE_H, NODE_W, edgePath } from './layout'
import type { CodeGraph, GraphNode } from './layout'

const MIN_SCALE = 0.28
const MAX_SCALE = 2.4

interface View {
  scale: number
  tx: number
  ty: number
}

const RETRIEVAL_FILL: Record<GraphNode['retrieval'], string> = {
  interpreted: 'url(#node-interpreted)',
  decompiled: 'var(--color-ground-3)',
  unretrieved: 'transparent',
}

function nodeStroke(node: GraphNode): string {
  if (node.isSink) return 'var(--color-critical)'
  if (node.isEntrypoint) return 'var(--color-v300)'
  return node.retrieval === 'unretrieved' ? 'var(--color-line-bright)' : 'var(--color-v600)'
}

export function GraphCanvas({
  graph,
  selectedId,
  focus,
  reached,
  onSelect,
}: {
  graph: CodeGraph
  selectedId: string | null
  /** Ids to keep at full opacity; null means "no filter, show everything". */
  focus: ReadonlySet<string> | null
  /** Ids already lit by the retrieval replay, in the order they were reached. */
  reached: ReadonlySet<string>
  onSelect: (id: string) => void
}) {
  const box = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ w: 0, h: 0 })
  const [view, setView] = useState<View>({ scale: 1, tx: 0, ty: 0 })
  const drag = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null)

  useLayoutEffect(() => {
    const element = box.current
    if (!element) return
    const observer = new ResizeObserver(([entry]) => {
      setSize({ w: entry.contentRect.width, h: entry.contentRect.height })
    })
    observer.observe(element)
    return () => observer.disconnect()
  }, [])

  const fit = useCallback(() => {
    if (!size.w || !size.h || !graph.width || !graph.height) return
    const scale = Math.min(
      MAX_SCALE,
      Math.max(MIN_SCALE, Math.min(size.w / graph.width, size.h / graph.height, 1.15)),
    )
    setView({
      scale,
      tx: (size.w - graph.width * scale) / 2,
      ty: (size.h - graph.height * scale) / 2,
    })
  }, [size.w, size.h, graph.width, graph.height])

  useEffect(fit, [fit])

  const zoomBy = useCallback(
    (factor: number, ox?: number, oy?: number) => {
      setView((current) => {
        const scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, current.scale * factor))
        const cx = ox ?? size.w / 2
        const cy = oy ?? size.h / 2
        const ratio = scale / current.scale
        return {
          scale,
          tx: cx - (cx - current.tx) * ratio,
          ty: cy - (cy - current.ty) * ratio,
        }
      })
    },
    [size.w, size.h],
  )

  // Non-passive so the page does not scroll out from under a zoom gesture.
  useEffect(() => {
    const element = box.current
    if (!element) return
    const onWheel = (event: WheelEvent) => {
      event.preventDefault()
      const rect = element.getBoundingClientRect()
      zoomBy(
        Math.exp(-event.deltaY * 0.0016),
        event.clientX - rect.left,
        event.clientY - rect.top,
      )
    }
    element.addEventListener('wheel', onWheel, { passive: false })
    return () => element.removeEventListener('wheel', onWheel)
  }, [zoomBy])

  const highlighted = (id: string) => focus === null || focus.has(id)

  return (
    <div
      ref={box}
      className="relative h-full w-full touch-none overflow-hidden bg-ground"
      onPointerDown={(event) => {
        if ((event.target as Element).closest('[data-node]')) return
        drag.current = { x: event.clientX, y: event.clientY, tx: view.tx, ty: view.ty }
        event.currentTarget.setPointerCapture(event.pointerId)
      }}
      onPointerMove={(event) => {
        const start = drag.current
        if (!start) return
        setView((current) => ({
          ...current,
          tx: start.tx + (event.clientX - start.x),
          ty: start.ty + (event.clientY - start.y),
        }))
      }}
      onPointerUp={() => {
        drag.current = null
      }}
      onPointerCancel={() => {
        drag.current = null
      }}
      style={{ cursor: drag.current ? 'grabbing' : 'grab' }}
    >
      {/* A faint violet grid so panning reads as movement over a surface. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.5]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(124,58,237,0.10) 1px, transparent 1px), linear-gradient(90deg, rgba(124,58,237,0.10) 1px, transparent 1px)',
          backgroundSize: `${34 * view.scale}px ${34 * view.scale}px`,
          backgroundPosition: `${view.tx}px ${view.ty}px`,
        }}
      />

      <svg width="100%" height="100%" className="relative block">
        <defs>
          <linearGradient id="node-interpreted" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#7b3fe4" />
            <stop offset="55%" stopColor="#a855f7" />
            <stop offset="100%" stopColor="#c084fc" />
          </linearGradient>
          <filter id="node-glow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="7" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <marker
            id="arrow"
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0 0 L8 4 L0 8 z" fill="var(--color-v500)" />
          </marker>
          <marker
            id="arrow-hot"
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0 0 L8 4 L0 8 z" fill="var(--color-magenta)" />
          </marker>
        </defs>

        <g transform={`translate(${view.tx} ${view.ty}) scale(${view.scale})`}>
          {graph.edges.map((edge) => {
            const from = graph.byId.get(edge.from)
            const to = graph.byId.get(edge.to)
            if (!from || !to) return null
            const lit = reached.has(edge.from) && reached.has(edge.to)
            const shown = highlighted(edge.from) && highlighted(edge.to)
            return (
              <path
                key={edge.id}
                d={edgePath(from, to)}
                fill="none"
                stroke={lit ? 'var(--color-magenta)' : 'var(--color-v500)'}
                strokeWidth={lit ? 2.4 : 1.4}
                strokeDasharray={edge.back ? '5 5' : lit ? '8 6' : undefined}
                className={lit && !edge.back ? 'anim-dash-flow' : undefined}
                markerEnd={lit ? 'url(#arrow-hot)' : 'url(#arrow)'}
                opacity={shown ? (lit ? 0.95 : 0.42) : 0.07}
                style={{ transition: 'opacity 260ms ease, stroke-width 260ms ease' }}
              />
            )
          })}

          {graph.nodes.map((node) => {
            const selected = node.id === selectedId
            const lit = reached.has(node.id)
            const shown = highlighted(node.id)
            return (
              <g
                key={node.id}
                data-node
                transform={`translate(${node.x} ${node.y})`}
                onClick={() => onSelect(node.id)}
                style={{
                  cursor: 'pointer',
                  opacity: shown ? 1 : 0.14,
                  transition: 'opacity 260ms ease',
                }}
              >
                <title>{node.id}</title>
                {(selected || lit) && (
                  <rect
                    x={-5}
                    y={-5}
                    width={NODE_W + 10}
                    height={NODE_H + 10}
                    rx={17}
                    fill="none"
                    stroke={lit ? 'var(--color-magenta)' : '#ffffff'}
                    strokeWidth={2}
                    opacity={selected ? 0.95 : 0.7}
                    filter="url(#node-glow)"
                  />
                )}
                <rect
                  width={NODE_W}
                  height={NODE_H}
                  rx={12}
                  fill={RETRIEVAL_FILL[node.retrieval]}
                  stroke={nodeStroke(node)}
                  strokeWidth={node.isSink || node.isEntrypoint ? 1.8 : 1.2}
                  strokeDasharray={node.retrieval === 'unretrieved' ? '4 4' : undefined}
                  filter={node.retrieval === 'interpreted' ? 'url(#node-glow)' : undefined}
                />
                <text
                  x={12}
                  y={21}
                  className="font-mono"
                  fontSize={12}
                  fill={node.retrieval === 'interpreted' ? '#ffffff' : 'var(--color-fg)'}
                >
                  {truncate(node.label, 22)}
                </text>
                <text
                  x={12}
                  y={37}
                  fontSize={9.5}
                  fill={
                    node.retrieval === 'interpreted'
                      ? 'rgba(255,255,255,0.75)'
                      : 'var(--color-dim)'
                  }
                >
                  {truncate(node.owner || '—', 30)}
                </text>
                {node.isSink && (
                  <circle cx={NODE_W - 13} cy={13} r={4.5} fill="var(--color-critical)" />
                )}
                {node.isEntrypoint && (
                  <rect
                    x={NODE_W - 19}
                    y={NODE_H - 18}
                    width={9}
                    height={9}
                    rx={2}
                    fill="var(--color-v300)"
                  />
                )}
              </g>
            )
          })}
        </g>
      </svg>

      <div className="absolute right-3 bottom-3 flex flex-col gap-1.5">
        {[
          { icon: Plus, label: 'Zoom in', run: () => zoomBy(1.25) },
          { icon: Minus, label: 'Zoom out', run: () => zoomBy(0.8) },
          { icon: Crosshair, label: 'Fit graph', run: fit },
        ].map(({ icon: Icon, label, run }) => (
          <button
            key={label}
            type="button"
            title={label}
            aria-label={label}
            onClick={run}
            className="glass flex h-8 w-8 items-center justify-center rounded-lg border border-line text-muted transition-colors hover:border-v400 hover:text-v300"
          >
            <Icon size={14} />
          </button>
        ))}
      </div>

      <div className="glass absolute bottom-3 left-3 rounded-lg border border-line px-3 py-2 text-[10px] text-dim">
        {Math.round(view.scale * 100)}% · drag to pan · scroll to zoom
      </div>
    </div>
  )
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value
}
