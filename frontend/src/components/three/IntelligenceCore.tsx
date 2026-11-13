'use client';
import { Canvas, useFrame } from '@react-three/fiber';
import { useMemo, useRef } from 'react';
import * as THREE from 'three';
import type { Stage } from '@/lib/types';
import { StudioEnv } from './EvidenceUniverse';

/** Visual parameters per REAL backend stage. The component has no timers or fake progress of its own:
 *  whatever `stage` the API reports is what is drawn. */
const STATE: Record<Stage, { ring: number; spin: number; arcs: number; breathe: number; align: number; accent: string; shell: number }> = {
  idle:                { ring: 0.06, spin: 0.05, arcs: 0.0,  breathe: 0.0,  align: 0, accent: '#B9C2CE', shell: 0.05 },
  evidence_collection: { ring: 0.35, spin: 0.18, arcs: 0.0,  breathe: 1.0,  align: 0, accent: '#FF9D35', shell: 0.07 },
  processing:          { ring: 0.9,  spin: 0.3,  arcs: 0.12, breathe: 0.25, align: 0, accent: '#FF9D35', shell: 0.08 },
  correlation:         { ring: 0.45, spin: 0.16, arcs: 1.0,  breathe: 0.1,  align: 0, accent: '#FF9D35', shell: 0.09 },
  verification:        { ring: 0.25, spin: 0.08, arcs: 0.6,  breathe: 0.0,  align: 1, accent: '#52D9E8', shell: 0.1 },
  completed:           { ring: 0.05, spin: 0.04, arcs: 0.45, breathe: 0.0,  align: 1, accent: '#52D9E8', shell: 0.08 },
  failed:              { ring: 0.0,  spin: 0.0,  arcs: 0.0,  breathe: 0.0,  align: 0, accent: '#E84B55', shell: 0.04 },
};
const N_POINTS = 260;
const N_ARCS = 90;

function fib(n: number, r: number): Float32Array {
  const out = new Float32Array(n * 3);
  const g = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < n; i++) {
    const y = 1 - (i / (n - 1)) * 2, rad = Math.sqrt(1 - y * y), t = g * i;
    out[i * 3] = Math.cos(t) * rad * r; out[i * 3 + 1] = y * r; out[i * 3 + 2] = Math.sin(t) * rad * r;
  }
  return out;
}

function Structure({ stage, still }: { stage: Stage; still: boolean }) {
  const group = useRef<THREE.Group>(null);
  const rings = useRef<THREE.Group>(null);
  const points = useRef<THREE.Points>(null);
  const arcs = useRef<THREE.LineSegments>(null);
  const cur = useRef({ ...STATE[stage] });
  const accent = useRef(new THREE.Color(STATE[stage].accent));
  const mats = useRef<{ ring: THREE.MeshBasicMaterial[]; pts?: THREE.PointsMaterial; arc?: THREE.LineBasicMaterial; core?: THREE.MeshStandardMaterial; shell?: THREE.MeshPhysicalMaterial }>({ ring: [] });

  const base = useMemo(() => fib(N_POINTS, 1.62), []);
  const pointGeo = useMemo(() => { const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.BufferAttribute(base.slice(), 3)); return g; }, [base]);
  const arcGeo = useMemo(() => {
    const v = new Float32Array(N_ARCS * 6);
    for (let i = 0; i < N_ARCS; i++) {
      const a = (i * 37) % N_POINTS, b = (i * 37 + 11 + (i % 7) * 13) % N_POINTS;
      v.set(base.subarray(a * 3, a * 3 + 3), i * 6); v.set(base.subarray(b * 3, b * 3 + 3), i * 6 + 3);
    }
    const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.BufferAttribute(v, 3)); return g;
  }, [base]);
  const lattice = useMemo(() => new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(1.3, 1)), []);
  const tilt = useMemo(() => [[1.1, 0.2, 0.0], [0.35, 0.0, 0.9], [1.45, 0.75, 0.3]] as const, []);

  useFrame((state, dt) => {
    const target = STATE[stage];
    const k = still ? 1 : Math.min(1, dt * 2.2);
    const c = cur.current;
    (['ring', 'spin', 'arcs', 'breathe', 'align', 'shell'] as const).forEach((p) => { c[p] += (target[p] - c[p]) * k; });
    accent.current.lerp(new THREE.Color(target.accent), k);
    const t = still ? 0 : state.clock.elapsedTime;
    if (group.current && !still) group.current.rotation.y += dt * c.spin;
    if (rings.current) {
      rings.current.children.forEach((r, i) => {
        const [tx, ty, tz] = tilt[i];
        r.rotation.x = THREE.MathUtils.lerp(tx, Math.PI / 2, c.align);
        r.rotation.y = THREE.MathUtils.lerp(ty, 0, c.align) + (still ? 0 : t * c.ring * (i % 2 ? -1 : 1) * (0.6 + i * 0.25));
        r.rotation.z = THREE.MathUtils.lerp(tz, 0, c.align);
      });
    }
    if (points.current) {
      const p = points.current.geometry.attributes.position as THREE.BufferAttribute;
      for (let i = 0; i < N_POINTS; i++) {
        // evidence collection: surface nodes are drawn in toward the core and released
        const s = 1 - c.breathe * 0.22 * (0.5 + 0.5 * Math.sin(t * 1.6 + i * 0.37));
        p.setXYZ(i, base[i * 3] * s, base[i * 3 + 1] * s, base[i * 3 + 2] * s);
      }
      p.needsUpdate = true;
    }
    if (arcs.current) arcs.current.geometry.setDrawRange(0, Math.round(N_ARCS * c.arcs) * 2);
    const m = mats.current;
    m.ring.forEach((x) => x.color.copy(accent.current));
    m.pts?.color.copy(accent.current);
    m.arc?.color.copy(accent.current);
    m.core?.emissive.copy(accent.current).multiplyScalar(stage === 'failed' ? 0.25 : 0.08);
    if (m.shell) m.shell.opacity = c.shell;
  });

  return (
    <group ref={group}>
      <mesh>
        <icosahedronGeometry args={[0.82, 1]} />
        <meshStandardMaterial ref={(x) => { if (x) mats.current.core = x; }} color="#8b97a6" metalness={0.95} roughness={0.24} flatShading />
      </mesh>
      <lineSegments geometry={lattice}><lineBasicMaterial color="#B9C2CE" transparent opacity={0.22} /></lineSegments>
      <mesh>
        <sphereGeometry args={[1.6, 48, 32]} />
        <meshPhysicalMaterial ref={(x) => { if (x) mats.current.shell = x; }} color="#9fb4c8" transparent opacity={0.07} roughness={0.15} metalness={0.2} depthWrite={false} side={THREE.DoubleSide} />
      </mesh>
      <points ref={points} geometry={pointGeo}>
        <pointsMaterial ref={(x) => { if (x) mats.current.pts = x; }} size={0.028} sizeAttenuation transparent opacity={0.9} depthWrite={false} />
      </points>
      <lineSegments ref={arcs} geometry={arcGeo}>
        <lineBasicMaterial ref={(x) => { if (x) mats.current.arc = x; }} transparent opacity={0.38} depthWrite={false} />
      </lineSegments>
      <group ref={rings}>
        {[1.95, 2.14, 2.34].map((r, i) => (
          <mesh key={r}>
            <torusGeometry args={[r, 0.005, 6, 200]} />
            <meshBasicMaterial ref={(x) => { if (x) mats.current.ring[i] = x; }} transparent opacity={0.75 - i * 0.18} />
          </mesh>
        ))}
      </group>
    </group>
  );
}

export default function IntelligenceCore({ stage, reducedMotion = false, className = '' }: { stage: Stage; reducedMotion?: boolean; className?: string }) {
  return (
    <div className={className} role="img" aria-label={`ARGUS intelligence core. Engine state: ${stage.replace(/_/g, ' ')}.`}>
      <Canvas camera={{ position: [0, 0.5, 8.6], fov: 36 }} dpr={[1, 1.75]} frameloop={reducedMotion ? 'demand' : 'always'} gl={{ antialias: true, alpha: true, powerPreference: 'low-power' }}>
        <StudioEnv intensity={0.7} />
        <ambientLight intensity={0.35} />
        <directionalLight position={[4, 5, 3]} intensity={2.2} color="#ffe9d2" />
        <directionalLight position={[-5, -2, -4]} intensity={1.4} color="#52D9E8" />
        <Structure stage={stage} still={reducedMotion} />
      </Canvas>
    </div>
  );
}
