'use client';
import { Html, OrbitControls } from '@react-three/drei';
import { Canvas, ThreeEvent, useFrame, useThree } from '@react-three/fiber';
import gsap from 'gsap';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import * as THREE from 'three';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';
import type { Graph, GraphNode } from '@/lib/types';
import { Indexed, NODE_TYPES, nodeHex } from '@/lib/graph';
import { short } from '@/lib/format';

/** One geometry + material per entity category (instanced). Shape tells you the category, colour the threat state. */
const SHAPES: Record<string, { geo: () => THREE.BufferGeometry; metalness: number; roughness: number; flat: boolean; size: number }> = {
  evidence: { geo: () => new THREE.OctahedronGeometry(0.62, 0), metalness: 0.85, roughness: 0.22, flat: true, size: 1 },
  ip: { geo: () => new THREE.SphereGeometry(0.3, 20, 14), metalness: 0.35, roughness: 0.35, flat: false, size: 1 },
  domain: { geo: () => new THREE.IcosahedronGeometry(0.36, 0), metalness: 0.6, roughness: 0.3, flat: true, size: 1 },
  url: { geo: () => new THREE.TetrahedronGeometry(0.42, 0), metalness: 0.5, roughness: 0.4, flat: true, size: 1 },
  email: { geo: () => new THREE.BoxGeometry(0.5, 0.34, 0.12), metalness: 0.4, roughness: 0.5, flat: true, size: 1 },
  sha256: { geo: () => new THREE.DodecahedronGeometry(0.36, 0), metalness: 0.8, roughness: 0.25, flat: true, size: 1 },
  user: { geo: () => new THREE.ConeGeometry(0.28, 0.56, 5), metalness: 0.3, roughness: 0.55, flat: true, size: 1 },
  host: { geo: () => new THREE.CylinderGeometry(0.34, 0.34, 0.22, 6), metalness: 0.7, roughness: 0.3, flat: true, size: 1 },
};
const M = new THREE.Matrix4(), Q = new THREE.Quaternion(), S = new THREE.Vector3(), V = new THREE.Vector3(), C = new THREE.Color();

export interface UniverseProps {
  graph: Graph; ix: Indexed; positions: Map<string, [number, number, number]>; visible: Set<string>;
  selected: string | null; onSelect: (id: string | null) => void; onExpand?: (id: string) => void;
  temporalDepth?: boolean; reducedMotion?: boolean; compact?: boolean; focusNonce?: number;
}

function useNodePos(p: UniverseProps) {
  return useMemo(() => {
    const t0 = p.graph.time_range.start ? Date.parse(p.graph.time_range.start) : 0;
    const t1 = p.graph.time_range.end ? Date.parse(p.graph.time_range.end) : 0;
    const span = Math.max(1, t1 - t0);
    const out = new Map<string, THREE.Vector3>();
    for (const n of p.graph.nodes) {
      const [x, y, z] = p.positions.get(n.id) || [0, 0, 0];
      // temporal depth: Z becomes time of first observation (earliest at the back)
      const zz = p.temporalDepth && n.first_seen ? -9 + (18 * (Date.parse(n.first_seen) - t0)) / span : z;
      out.set(n.id, new THREE.Vector3(x, y, p.temporalDepth && !n.first_seen ? -9 : zz));
    }
    return out;
  }, [p.graph, p.positions, p.temporalDepth]);
}

function Nodes({ p, pos, hovered, setHovered }: { p: UniverseProps; pos: Map<string, THREE.Vector3>; hovered: string | null; setHovered: (id: string | null) => void }) {
  const byType = useMemo(() => {
    const m: Record<string, GraphNode[]> = {};
    for (const n of p.graph.nodes) (m[n.type] ||= []).push(n);
    return m;
  }, [p.graph]);
  const refs = useRef<Record<string, THREE.InstancedMesh | null>>({});
  const geos = useMemo(() => Object.fromEntries(NODE_TYPES.map((t) => [t, SHAPES[t].geo()])), []);
  const neighbours = useMemo(() => new Set((p.selected ? p.ix.adj.get(p.selected) || [] : []).map((l) => l.other)), [p.selected, p.ix]);

  useLayoutEffect(() => {
    for (const t of NODE_TYPES) {
      const mesh = refs.current[t]; const list = byType[t] || [];
      if (!mesh) continue;
      list.forEach((n, i) => {
        const vis = p.visible.has(n.id);
        const emphasis = n.id === p.selected ? 1.45 : n.id === hovered ? 1.25 : 1;
        const base = (n.type === 'evidence' ? 1 : 0.8 + Math.min(0.6, (n.sources - 1) * 0.3)) * (p.compact ? 1.35 : 1);
        S.setScalar(vis ? base * emphasis : 0.0001);
        M.compose(pos.get(n.id) || V.set(0, 0, 0), Q, S);
        mesh.setMatrixAt(i, M);
        C.set(nodeHex(n));
        if (p.selected && n.id !== p.selected && !neighbours.has(n.id)) C.multiplyScalar(0.35);
        mesh.setColorAt(i, C);
      });
      mesh.count = list.length;
      mesh.instanceMatrix.needsUpdate = true;
      if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
      mesh.computeBoundingSphere();
    }
  }, [byType, pos, p.visible, p.selected, p.compact, hovered, neighbours]);

  const pick = (t: string, e: ThreeEvent<MouseEvent | PointerEvent>) => (e.instanceId != null ? (byType[t] || [])[e.instanceId] : undefined);
  return (
    <>
      {NODE_TYPES.map((t) => (byType[t]?.length ? (
        <instancedMesh key={`${t}-${byType[t].length}`} ref={(m) => { refs.current[t] = m; }} args={[geos[t], undefined, byType[t].length]}
          onPointerMove={(e) => { const n = pick(t, e); if (n && p.visible.has(n.id)) { e.stopPropagation(); setHovered(n.id); document.body.style.cursor = 'pointer'; } }}
          onPointerOut={() => { setHovered(null); document.body.style.cursor = ''; }}
          onClick={(e) => { const n = pick(t, e); if (n && p.visible.has(n.id)) { e.stopPropagation(); p.onSelect(n.id); } }}
          onDoubleClick={(e) => { const n = pick(t, e); if (n && n.type === 'evidence' && p.onExpand) { e.stopPropagation(); p.onExpand(n.id); } }}>
          <meshStandardMaterial metalness={SHAPES[t].metalness} roughness={SHAPES[t].roughness} flatShading={SHAPES[t].flat} />
        </instancedMesh>
      ) : null))}
    </>
  );
}

function Edges({ p, pos }: { p: UniverseProps; pos: Map<string, THREE.Vector3> }) {
  const { solid, dashed, hot } = useMemo(() => {
    const sp: number[] = [], sc: number[] = [], dp: number[] = [], hp: number[] = [];
    for (const e of p.graph.edges) {
      if (!p.visible.has(e.source) || !p.visible.has(e.target)) continue;
      const a = pos.get(e.source), b = pos.get(e.target);
      if (!a || !b) continue;
      const touches = p.selected && (e.source === p.selected || e.target === p.selected);
      if (touches) { hp.push(a.x, a.y, a.z, b.x, b.y, b.z); continue; }
      if (e.basis === 'inferred') { dp.push(a.x, a.y, a.z, b.x, b.y, b.z); continue; }
      const k = (e.relation === 'contains' ? 0.16 : e.basis === 'observed' ? 0.5 : 0.3) * (p.selected ? 0.45 : 1);
      sp.push(a.x, a.y, a.z, b.x, b.y, b.z); sc.push(0.72 * k, 0.76 * k, 0.81 * k, 0.72 * k, 0.76 * k, 0.81 * k);
    }
    const mk = (arr: number[], col?: number[]) => { const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.Float32BufferAttribute(arr, 3)); if (col) g.setAttribute('color', new THREE.Float32BufferAttribute(col, 3)); return g; };
    return { solid: mk(sp, sc), dashed: mk(dp), hot: mk(hp) };
  }, [p.graph, p.visible, p.selected, pos]);
  const dashedRef = useRef<THREE.LineSegments>(null);
  useEffect(() => { dashedRef.current?.computeLineDistances(); }, [dashed]);
  useEffect(() => () => { solid.dispose(); dashed.dispose(); hot.dispose(); }, [solid, dashed, hot]);
  return (
    <>
      <lineSegments geometry={solid}><lineBasicMaterial vertexColors transparent opacity={0.9} depthWrite={false} /></lineSegments>
      <lineSegments ref={dashedRef} geometry={dashed}><lineDashedMaterial color="#B9C2CE" dashSize={0.22} gapSize={0.16} transparent opacity={0.4} depthWrite={false} /></lineSegments>
      <lineSegments geometry={hot}><lineBasicMaterial color="#FF9D35" transparent opacity={0.95} depthWrite={false} /></lineSegments>
    </>
  );
}

/** Restrained halo behind high-severity entities (additive points, no post-processing pass). */
function Halos({ p, pos }: { p: UniverseProps; pos: Map<string, THREE.Vector3> }) {
  const geo = useMemo(() => {
    const arr: number[] = [];
    for (const n of p.graph.nodes) if ((n.severity === 'high' || n.severity === 'critical') && p.visible.has(n.id)) { const v = pos.get(n.id); if (v) arr.push(v.x, v.y, v.z); }
    const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.Float32BufferAttribute(arr, 3)); return g;
  }, [p.graph, p.visible, pos]);
  const tex = useMemo(() => {
    const c = document.createElement('canvas'); c.width = c.height = 64;
    const ctx = c.getContext('2d')!; const gr = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    gr.addColorStop(0, 'rgba(232,75,85,0.55)'); gr.addColorStop(0.4, 'rgba(232,75,85,0.16)'); gr.addColorStop(1, 'rgba(232,75,85,0)');
    ctx.fillStyle = gr; ctx.fillRect(0, 0, 64, 64);
    return new THREE.CanvasTexture(c);
  }, []);
  return <points geometry={geo}><pointsMaterial map={tex} size={2.4} sizeAttenuation transparent depthWrite={false} blending={THREE.AdditiveBlending} /></points>;
}

function Labels({ p, pos, hovered }: { p: UniverseProps; pos: Map<string, THREE.Vector3>; hovered: string | null }) {
  const ids = useMemo(() => {
    const out = new Set<string>();
    if (p.selected) { out.add(p.selected); if (!p.compact) for (const l of (p.ix.adj.get(p.selected) || []).slice(0, 14)) out.add(l.other); }
    if (hovered) out.add(hovered);
    if (!p.compact && !p.selected) {
      const vis = p.graph.nodes.filter((n) => p.visible.has(n.id));
      const pri = vis.length <= 28 ? vis : vis.filter((n) => n.type === 'evidence' || n.severity === 'high' || n.severity === 'critical' || n.sources > 1).slice(0, 26);
      pri.forEach((n) => out.add(n.id));
    }
    return [...out].filter((id) => p.visible.has(id));
  }, [p.selected, p.visible, p.graph, p.ix, p.compact, hovered]);
  return (
    <>
      {ids.map((id) => {
        const n = p.ix.byId.get(id)!; const v = pos.get(id)!;
        const extra = n.type === 'evidence' && p.graph.nodes.length > 60 ? p.ix.clusterSize.get(id) : 0;
        return (
          <Html key={id} position={[v.x, v.y + (n.type === 'evidence' ? 0.95 : 0.62), v.z]} center zIndexRange={[20, 0]} style={{ pointerEvents: 'none' }}>
            <div className={`whitespace-nowrap border px-1.5 py-[1px] font-mono text-[10px] leading-4 backdrop-blur-sm ${id === p.selected ? 'border-amber bg-obsidian/90 text-amber' : 'border-line bg-obsidian/70 text-titanium'}`}>
              {short(n.label, 34)}{extra ? <span className="text-titanium-mute"> +{extra}</span> : null}
            </div>
          </Html>
        );
      })}
    </>
  );
}

function Rig({ p, pos }: { p: UniverseProps; pos: Map<string, THREE.Vector3> }) {
  const { camera, invalidate } = useThree();
  const controls = useRef<any>(null);
  const ring = useRef<THREE.Mesh>(null);
  const first = useRef(true);
  // Smooth camera transition to the selected entity (GSAP). Instant when reduced motion is requested.
  useEffect(() => {
    const c = controls.current; if (!c) return;
    let target: THREE.Vector3, dist: number;
    if (p.selected && pos.get(p.selected) && p.visible.has(p.selected)) { target = pos.get(p.selected)!.clone(); dist = p.compact ? 16 : 18; }
    else {
      const pts = [...p.visible].map((id) => pos.get(id)).filter(Boolean) as THREE.Vector3[];
      const box = new THREE.Box3(); pts.forEach((v) => box.expandByPoint(v));
      target = pts.length ? box.getCenter(new THREE.Vector3()) : new THREE.Vector3();
      dist = pts.length ? Math.max(9, box.getSize(new THREE.Vector3()).length() * (p.compact ? 0.72 : 0.8)) : 24;
    }
    const dir = camera.position.clone().sub(c.target); if (dir.lengthSq() < 0.01) dir.set(0, 0.25, 1);
    const dest = target.clone().add(dir.normalize().multiplyScalar(dist));
    const dur = p.reducedMotion || first.current ? 0 : 0.9;
    first.current = false;
    gsap.killTweensOf([camera.position, c.target]);
    gsap.to(camera.position, { x: dest.x, y: dest.y, z: dest.z, duration: dur, ease: 'power3.inOut', onUpdate: invalidate });
    gsap.to(c.target, { x: target.x, y: target.y, z: target.z, duration: dur, ease: 'power3.inOut', onUpdate: () => { c.update(); invalidate(); } });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [p.selected, p.focusNonce, pos, p.temporalDepth]);
  useFrame(({ camera: cam }) => { if (ring.current && p.selected && pos.get(p.selected)) { ring.current.position.copy(pos.get(p.selected)!); ring.current.quaternion.copy(cam.quaternion); } });
  return (
    <>
      <OrbitControls ref={controls} makeDefault enableDamping={!p.reducedMotion} dampingFactor={0.08} rotateSpeed={0.7} zoomSpeed={0.8} panSpeed={0.8} minDistance={2.5} maxDistance={90}
        autoRotate={!!p.compact && !p.reducedMotion && !p.selected} autoRotateSpeed={0.35} />
      {p.selected && p.visible.has(p.selected) && <mesh ref={ring}><ringGeometry args={[0.92, 0.96, 48]} /><meshBasicMaterial color="#FF9D35" transparent opacity={0.9} side={THREE.DoubleSide} depthTest={false} /></mesh>}
    </>
  );
}

/** Procedural studio environment (no network, no HDR file) so metallic materials read as dark titanium rather than black. */
export function StudioEnv({ intensity = 0.55 }: { intensity?: number }) {
  const { gl, scene } = useThree();
  useEffect(() => {
    const pmrem = new THREE.PMREMGenerator(gl);
    const tex = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
    scene.environment = tex;
    (scene as any).environmentIntensity = intensity;
    return () => { scene.environment = null; tex.dispose(); pmrem.dispose(); };
  }, [gl, scene, intensity]);
  return null;
}

export default function EvidenceUniverse(p: UniverseProps) {
  const [hovered, setHovered] = useState<string | null>(null);
  const pos = useNodePos(p);
  return (
    <Canvas camera={{ position: [0, 4, 26], fov: 42, near: 0.1, far: 400 }} dpr={[1, 1.75]} frameloop={p.reducedMotion ? 'demand' : 'always'} gl={{ antialias: true, alpha: true, powerPreference: 'high-performance' }}
      onPointerMissed={() => p.onSelect(null)} aria-label="Three-dimensional evidence graph">
      <fog attach="fog" args={['#080A0E', 28, 95]} />
      <StudioEnv />
      <ambientLight intensity={0.5} />
      <directionalLight position={[10, 14, 8]} intensity={2.4} color="#fff1e0" />
      <directionalLight position={[-12, -6, -10]} intensity={1.1} color="#52D9E8" />
      <Edges p={p} pos={pos} />
      <Halos p={p} pos={pos} />
      <Nodes p={p} pos={pos} hovered={hovered} setHovered={setHovered} />
      <Labels p={p} pos={pos} hovered={hovered} />
      <Rig p={p} pos={pos} />
    </Canvas>
  );
}
