import React, { useEffect, useMemo, useState, useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import {
  OrbitControls,
  Float,
  Text,
  Stars,
} from "@react-three/drei";

const API_URL = "http://127.0.0.1:8001";

/* =========================================================
   HOST NODE
   ========================================================= */

function Host({ position, name, ip, eventCount, color, threatCount, riskScore, status }) {
  return (
    <Float speed={2} rotationIntensity={0.15} floatIntensity={0.25}>
      <group position={position}>
        <mesh>
          <sphereGeometry args={[0.72, 32, 32]} />
          <meshStandardMaterial
            color={color}
            emissive={color}
            emissiveIntensity={0.45}
          />
        </mesh>

        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[0.9, 0.025, 16, 64]} />
          <meshBasicMaterial
            color={color}
            transparent
            opacity={0.7}
          />
        </mesh>

        <Text
          position={[0, -1.05, 0]}
          fontSize={0.22}
          color="white"
          anchorX="center"
          anchorY="middle"
        >
          {name}
        </Text>

        <Text
          position={[0, -1.32, 0]}
          fontSize={0.15}
          color="#94a3b8"
          anchorX="center"
          anchorY="middle"
        >
          {ip}
        </Text>

        <Text
          position={[0, -1.55, 0]}
          fontSize={0.12}
          color="#38bdf8"
          anchorX="center"
          anchorY="middle"
        >
          {`${eventCount} events`}
        </Text>

        <Text
          position={[0, -1.78, 0]}
          fontSize={0.13}
          color={color}
          anchorX="center"
          anchorY="middle"
        >
          {`${status} | Risk ${riskScore}`}
        </Text>

        <Text
          position={[0, -2.00, 0]}
          fontSize={0.12}
          color={threatCount > 0 ? "#f87171" : "#94a3b8"}
          anchorX="center"
          anchorY="middle"
        >
          {`${threatCount} threats`}
        </Text>
      </group>
    </Float>
  );
}

/* =========================================================
   SIEM SERVER
   ========================================================= */

function SiemServer() {
  return (
    <Float speed={1.5} floatIntensity={0.2}>
      <group position={[0, 0, 0]}>
        <mesh>
          <icosahedronGeometry args={[0.85, 1]} />
          <meshStandardMaterial
            color="#06b6d4"
            emissive="#06b6d4"
            emissiveIntensity={0.55}
          />
        </mesh>

        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[1.05, 0.035, 16, 64]} />
          <meshBasicMaterial color="#22d3ee" />
        </mesh>

        <Text
          position={[0, -1.25, 0]}
          fontSize={0.25}
          color="white"
          anchorX="center"
        >
          SIEM SERVER
        </Text>

        <Text
          position={[0, -1.52, 0]}
          fontSize={0.14}
          color="#67e8f9"
          anchorX="center"
        >
          REAL-TIME
        </Text>
      </group>
    </Float>
  );
}

/* =========================================================
   CONNECTION LINE
   ========================================================= */

function Connection({ start, end }) {
  const dx = end[0] - start[0];
  const dy = end[1] - start[1];
  const dz = end[2] - start[2];

  const length = Math.sqrt(dx * dx + dy * dy + dz * dz);

  const midpoint = [
    (start[0] + end[0]) / 2,
    (start[1] + end[1]) / 2,
    (start[2] + end[2]) / 2,
  ];

  const angle = Math.atan2(dz, dx);

  return (
    <mesh
      position={midpoint}
      rotation={[0, angle, 0]}
    >
      <boxGeometry args={[length, 0.025, 0.025]} />
      <meshBasicMaterial
        color="#38bdf8"
        transparent
        opacity={0.75}
      />
    </mesh>
  );
}

/* =========================================================
   ANIMATED DATA PACKETS
   ========================================================= */

function DataPacket({
  start,
  end,
  color = "#facc15",
  speed = 0.45,
  offset = 0,
}) {
  const packetRef = useRef(null);

  useFrame(({ clock }) => {
    if (!packetRef.current) return;

    const progress =
      (clock.elapsedTime * speed + offset) % 1;

    packetRef.current.position.set(
      start[0] + (end[0] - start[0]) * progress,
      start[1] + (end[1] - start[1]) * progress,
      start[2] + (end[2] - start[2]) * progress
    );
  });

  return (
    <mesh ref={packetRef}>
      <sphereGeometry args={[0.09, 16, 16]} />
      <meshStandardMaterial
        color={color}
        emissive={color}
        emissiveIntensity={1.8}
        toneMapped={false}
      />
    </mesh>
  );
}

/* =========================================================
   HOST IP LOOKUP
   ========================================================= */

function getHostIp(hostname) {
  const knownHosts = {
    VankadaraRakesh: "10.0.7.203",
    "LAPTOP-E8HKB32S": "10.0.7.109",
  };

  return knownHosts[hostname] || "IP detected from logs";
}

/* =========================================================
   HOST STATUS COLORS
   ========================================================= */

function getStatusColor(host) {
  const status = String(host.status || host.severity || "NORMAL").toUpperCase();

  if (status === "CRITICAL" || status === "HIGH") return "#ef4444";
  if (status === "WARNING" || status === "MEDIUM") return "#facc15";
  return "#22c55e";
}

/* =========================================================
   MAIN NETWORK COMPONENT
   ========================================================= */

export default function Network3D() {
  const [hosts, setHosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  /* LOAD MONITORED HOSTS */

  const fetchHosts = async () => {
    try {
      const token = sessionStorage.getItem("siem_token");
      const response = await fetch(`${API_URL}/hosts`, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error("Failed to load hosts");
      }

      const data = await response.json();

      setHosts(Array.isArray(data.hosts) ? data.hosts : []);
      setError(false);

    } catch (err) {
      console.error("Network topology error:", err);
      setError(true);

    } finally {
      setLoading(false);
    }
  };

  /* INITIAL LOAD + AUTO REFRESH */

  useEffect(() => {
    fetchHosts();

    const interval = setInterval(fetchHosts, 10000);

    return () => clearInterval(interval);
  }, []);

  /* CREATE HOST POSITIONS */

  const positionedHosts = useMemo(() => {
    if (!hosts.length) return [];

    const radius = 3.2;

    return hosts.map((host, index) => {
      const angle =
        (index / hosts.length) * Math.PI * 2;

      return {
        ...host,
        position: [
          Math.cos(angle) * radius,
          0,
          Math.sin(angle) * radius,
        ],
      };
    });
  }, [hosts]);

  const siemPosition = [0, 0, 0];

  const criticalHosts = hosts.filter((host) =>
    ["CRITICAL", "HIGH"].includes(String(host.status || host.severity || "").toUpperCase())
  ).length;
  const warningHosts = hosts.filter((host) =>
    ["WARNING", "MEDIUM"].includes(String(host.status || host.severity || "").toUpperCase())
  ).length;
  const totalThreats = hosts.reduce(
    (sum, host) => sum + Number(host.threat_count || 0),
    0
  );

  return (
    <div
      style={{
        width: "100%",
        height: "420px",
        background: "#080f1c",
        borderRadius: "16px",
        overflow: "hidden",
        border: "1px solid #263244",
        position: "relative",
      }}
    >
      {/* STATUS */}

      <div
        style={{
          position: "absolute",
          top: "14px",
          right: "18px",
          zIndex: 10,
          padding: "7px 12px",
          borderRadius: "20px",
          background: "rgba(8,15,28,0.8)",
          border: "1px solid #263244",
          color: criticalHosts > 0 ? "#f87171" : warningHosts > 0 ? "#facc15" : "#4ade80",
          fontSize: "11px",
          fontWeight: "700",
        }}
      >
        ● {hosts.length} HOST
        {hosts.length !== 1 ? "S" : ""} MONITORED
        {" | "}{totalThreats} THREATS
      </div>

      {/* THREAT STATUS LEGEND */}
      <div
        style={{
          position: "absolute",
          left: "16px",
          top: "14px",
          zIndex: 10,
          display: "flex",
          flexWrap: "wrap",
          gap: "10px",
          padding: "7px 10px",
          borderRadius: "12px",
          background: "rgba(8,15,28,0.82)",
          border: "1px solid #263244",
          color: "#cbd5e1",
          fontSize: "10px",
          fontWeight: "700",
        }}
      >
        <span style={{ color: "#4ade80" }}>● NORMAL</span>
        <span style={{ color: "#facc15" }}>● WARNING ({warningHosts})</span>
        <span style={{ color: "#f87171" }}>● CRITICAL ({criticalHosts})</span>
      </div>

      {/* LOADING */}

      {loading && (
        <div
          style={{
            position: "absolute",
            inset: 0,
            zIndex: 20,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "#38bdf8",
            fontSize: "14px",
            background: "rgba(8,15,28,0.65)",
          }}
        >
          Loading monitored hosts...
        </div>
      )}

      {/* ERROR */}

      {error && (
        <div
          style={{
            position: "absolute",
            bottom: "15px",
            left: "50%",
            transform: "translateX(-50%)",
            zIndex: 20,
            padding: "7px 12px",
            borderRadius: "8px",
            background: "rgba(127,29,29,0.85)",
            border: "1px solid #ef4444",
            color: "#fecaca",
            fontSize: "11px",
          }}
        >
          Unable to refresh host data
        </div>
      )}

      {/* 3D CANVAS */}

      <Canvas
        camera={{
          position: [0, 3, 8],
          fov: 50,
        }}
      >
        {/* LIGHTING */}

        <ambientLight intensity={0.5} />

        <pointLight
          position={[0, 4, 4]}
          intensity={2}
          color="#38bdf8"
        />

        <pointLight
          position={[-4, 2, -4]}
          intensity={1}
          color="#22c55e"
        />

        {/* BACKGROUND STARS */}

        <Stars
          radius={30}
          depth={15}
          count={600}
          factor={2}
          saturation={0}
          fade
          speed={0.4}
        />

        {/* GRID */}

        <gridHelper
          args={[14, 14, "#263244", "#111827"]}
        />

        {/* SIEM SERVER */}

        <SiemServer />

        {/* MONITORED HOSTS */}

        {positionedHosts.map((host) => (
          <React.Fragment key={host.hostname}>
            <Host
              position={host.position}
              name={host.hostname}
              ip={getHostIp(host.hostname)}
              eventCount={host.event_count || 0}
              threatCount={host.threat_count || 0}
              riskScore={host.risk_score || 0}
              status={host.status || host.severity || "NORMAL"}
              color={getStatusColor(host)}
            />

            {/* CONNECTION */}

            <Connection
              start={siemPosition}
              end={host.position}
            />

            {/* YELLOW PACKET: SIEM TO HOST */}

            <DataPacket
              start={siemPosition}
              end={host.position}
              color={getStatusColor(host) === "#ef4444" ? "#ef4444" : getStatusColor(host) === "#facc15" ? "#facc15" : "#38bdf8"}
              speed={getStatusColor(host) === "#ef4444" ? 0.55 : 0.32}
              offset={0}
            />

            {/* BLUE PACKET: HOST TO SIEM */}

            <DataPacket
              start={host.position}
              end={siemPosition}
              color={getStatusColor(host) === "#ef4444" ? "#f87171" : "#38bdf8"}
              speed={0.24}
              offset={0.5}
            />
          </React.Fragment>
        ))}

        {/* CAMERA CONTROLS */}

        <OrbitControls
          enablePan={false}
          minDistance={5}
          maxDistance={12}
          autoRotate={false}
        />
      </Canvas>

      {/* EMPTY STATE */}

      {!loading && hosts.length === 0 && (
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            pointerEvents: "none",
            color: "#94a3b8",
          }}
        >
          <div
            style={{
              fontSize: "15px",
              fontWeight: "700",
              color: "#e2e8f0",
            }}
          >
            No monitored hosts
          </div>

          <div
            style={{
              marginTop: "6px",
              fontSize: "12px",
            }}
          >
            Waiting for security log sources...
          </div>
        </div>
      )}
    </div>
  );
}