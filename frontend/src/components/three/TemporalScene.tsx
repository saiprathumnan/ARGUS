'use client';
import { Html, OrbitControls } from '@react-three/drei';
import { Canvas, ThreeEvent, useThree } from '@react-three/fiber';
import { useEffect, useLayoutEffect, useMemo, useRef } from 'react';
import { StudioEnv } from './EvidenceUniverse';
import * as THREE from 'three';
import type { Timeline, TimelineEntry } from '@/lib/types';
import { SEV_HEX } from '@/lib/format';

const LEN = 24; // world length of the time axis
const M = new THREE.Matrix4(), Q = new THREE.Quaternion(), S = new THREE.Vector3(), V = new THREE.Vector3(), C = new THREE.Color();

export interface TemporalProps { timeline: Timeline; playhead: number; selected: string | null; onSelect: (id: string | null) => void; highlight: Set<string>; reducedMotion?: boolean }

/** Events on spatial layers: X = time, depth = event category. Solid blocks carry timestamps recorded in evidence;
 *  wireframe blocks have an inferred or submission-time position. */
function Scene({ timeline, playhead, selected, onSelect, highlight }: TemporalProps) {
  const t0 = Date.parse(timeline.range!.start), t1 = Date.parse(timeline.range!.end), span = Math.max(1, t1 - t0);
  const layers = timeline.layers;
  const x = (iso: string) => -LEN / 2 + (LEN * (Date.parse(iso) - t0)) / span;
  const z = (layer: string) => (layers.indexOf(layer) - (layers.length - 1) / 2) * 2.2;
  const confirmed = useMemo(() => timeline.entries.filter((e) => e.time_basis === 'confirmed'), [timeline]);
  const inferred = useMemo(() => timeline.entries.filter((e) => e.time_basis !== 'confirmed'), [timeline]);
  const solid = useRef<THREE.InstancedMesh>(null), wire = useRef<THREE.InstancedMesh>(null);
  const cutoff = t0 + span * playhead;

  useLayoutEffect(() => {
    const paint = (mesh: THREE.InstancedMesh | null, list: TimelineEntry[]) => {
      if (!mesh) return;
      list.forEach((e, i) => {
        const h = e.severity === 'info' ? 0.25 : e.severity === 'low' ? 0.5 : e.severity === 'medium' ? 0.9 : 1.4;
        const sel = e.id === selected;
        S.set(sel ? 0.3 : 0.17, h * (sel ? 1.15 : 1), sel ? 1.0 : 0.7);
        M.compose(V.set(x(e.at), h / 2 + 0.02, z(e.layer)), Q, S);
        mesh.setMatrixAt(i, M);
        C.set(sel ? '#FF9D35' : highlight.has(e.id) ? '#52D9E8' : SEV_HEX[e.severity]);
        if (Date.parse(e.at) > cutoff) C.multiplyScalar(0.16); // not yet reached by the playhead
        else if (selected && !sel && !highlight.has(e.id)) C.multiplyScalar(0.5);
        mesh.setColorAt(i, C);
      });
      mesh.count = list.length;
      mesh.instanceMatrix.needsUpdate = true;
      if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
      mesh.computeBoundingSphere();
    };
    paint(solid.current, confirmed); paint(wire.current, inferred);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [confirmed, inferred, selected, highlight, cutoff]);

  const seq = useMemo(() => {
    const steps = (timeline.attack_sequence?.steps || []).filter((s) => s.at);
    const byFinding = new Map<string, TimelineEntry>();
    for (const e of timeline.entries) for (const f of e.finding_ids) if (!byFinding.has(f)) byFinding.set(f, e);
    const pts: number[] = [];
    let prev: THREE.Vector3 | null = null;
    for (const s of steps) {
      const e = byFinding.get(s.finding_id); if (!e) continue;
      const p = new THREE.Vector3(x(e.at), 1.9, z(e.layer));
      if (prev && prev.distanceTo(p) > 0.05) pts.push(prev.x, prev.y, prev.z, p.x, p.y, p.z);
      prev = p;
    }
    const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.Float32BufferAttribute(pts, 3)); return g;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeline]);
  const seqRef = useRef<THREE.LineSegments>(null);
  useLayoutEffect(() => { seqRef.current?.computeLineDistances(); }, [seq]);

  const pick = (list: TimelineEntry[]) => (e: ThreeEvent<MouseEvent>) => { if (e.instanceId != null && list[e.instanceId]) { e.stopPropagation(); onSelect(list[e.instanceId].id); } };
  const ticks = useMemo(() => Array.from({ length: 7 }, (_, i) => ({ px: -LEN / 2 + (LEN * i) / 6, label: new Date(t0 + (span * i) / 6).toISOString().slice(11, 19), date: new Date(t0 + (span * i) / 6).toISOString().slice(5, 10) })), [t0, span]);
  const depth = layers.length * 2.2;

  return (
    <>
      {layers.map((l) => (
        <group key={l} position={[0, 0, z(l)]}>
          <mesh rotation={[-Math.PI / 2, 0, 0]}><planeGeometry args={[LEN + 1.2, 1.7]} /><meshBasicMaterial color="#1D242E" transparent opacity={0.55} depthWrite={false} /></mesh>
          <Html position={[-LEN / 2 - 0.9, 0, 0]} center style={{ pointerEvents: 'none' }}><div className="whitespace-nowrap font-mono text-[10px] uppercase tracking-[0.14em] text-titanium">{l}</div></Html>
        </group>
      ))}
      {ticks.map((t, i) => (
        <group key={i} position={[t.px, 0, depth / 2 + 0.3]}>
          <mesh position={[0, 0, -depth / 2 - 0.3]} rotation={[-Math.PI / 2, 0, 0]}><planeGeometry args={[0.012, depth + 0.6]} /><meshBasicMaterial color="#B9C2CE" transparent opacity={0.14} /></mesh>
          <Html center style={{ pointerEvents: 'none' }}><div className="whitespace-nowrap text-center font-mono text-[9px] leading-3 text-titanium-mute">{t.label}<br />{t.date}</div></Html>
        </group>
      ))}
      <instancedMesh key={`s${confirmed.length}`} ref={solid} args={[undefined, undefined, Math.max(1, confirmed.length)]} onClick={pick(confirmed)}
        onPointerOver={() => { document.body.style.cursor = 'pointer'; }} onPointerOut={() => { document.body.style.cursor = ''; }}>
        <boxGeometry args={[1, 1, 1]} /><meshStandardMaterial metalness={0.5} roughness={0.35} />
      </instancedMesh>
      <instancedMesh key={`w${inferred.length}`} ref={wire} args={[undefined, undefined, Math.max(1, inferred.length)]} onClick={pick(inferred)}
        onPointerOver={() => { document.body.style.cursor = 'pointer'; }} onPointerOut={() => { document.body.style.cursor = ''; }}>
        <boxGeometry args={[1, 1, 1]} /><meshBasicMaterial wireframe />
      </instancedMesh>
      <lineSegments ref={seqRef} geometry={seq}><lineDashedMaterial color="#FF9D35" dashSize={0.3} gapSize={0.2} transparent opacity={0.85} /></lineSegments>
      {/* playhead */}
      <mesh position={[-LEN / 2 + LEN * playhead, 1.1, 0]}><planeGeometry args={[0.02, 2.4]} /><meshBasicMaterial color="#FF9D35" side={THREE.DoubleSide} transparent opacity={0.9} /></mesh>
      <mesh position={[-LEN / 2 + LEN * playhead, 0.01, 0]} rotation={[-Math.PI / 2, 0, 0]}><planeGeometry args={[0.03, depth + 0.6]} /><meshBasicMaterial color="#FF9D35" transparent opacity={0.7} /></mesh>
    </>
  );
}

/** Orthographic framing: the whole time axis and every layer stay in view at any panel size, with no perspective convergence. */
function FitCamera({ layers }: { layers: number }) {
  const { camera, size, invalidate } = useThree();
  useEffect(() => {
    const cam = camera as THREE.OrthographicCamera;
    const depth = layers * 2.2;
    cam.position.set(0, 12, 20);
    cam.lookAt(0, 0.4, 0);
    cam.zoom = Math.max(8, Math.min(size.width / (LEN + 7), size.height / (depth * 0.52 + 3.6)));
    cam.updateProjectionMatrix();
    invalidate();
  }, [camera, size.width, size.height, layers, invalidate]);
  return null;
}

export default function TemporalScene(p: TemporalProps) {
  if (!p.timeline.range) return null;
  return (
    <Canvas orthographic camera={{ position: [0, 12, 20], zoom: 30, near: -200, far: 400 }} dpr={[1, 1.75]} frameloop={p.reducedMotion ? 'demand' : 'always'} gl={{ antialias: true, alpha: true }} onPointerMissed={() => p.onSelect(null)} aria-label="Three-dimensional incident timeline">
      <FitCamera layers={p.timeline.layers.length} />
      <StudioEnv intensity={0.4} />
      <ambientLight intensity={0.7} />
      <directionalLight position={[6, 12, 8]} intensity={2} color="#fff1e0" />
      <directionalLight position={[-8, 4, -8]} intensity={0.9} color="#52D9E8" />
      <Scene {...p} />
      <OrbitControls makeDefault enableDamping={!p.reducedMotion} dampingFactor={0.08} minZoom={6} maxZoom={160} maxPolarAngle={Math.PI / 2.05} target={[0, 0.4, 0]} />
    </Canvas>
  );
}
