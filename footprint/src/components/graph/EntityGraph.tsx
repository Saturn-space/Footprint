import React, { useState, useMemo, useRef } from 'react';
import {
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  Filter,
  Download,
  Share2,
  SlidersHorizontal,
  Info
} from 'lucide-react';
import { Entity, Relationship, EntityType, RelationshipType, Evidence } from '../../types/models';
import { NodeDetailDrawer } from './NodeDetailDrawer';

interface EntityGraphProps {
  entities: Entity[];
  relationships: Relationship[];
  evidenceList: Evidence[];
}

export const ENTITY_COLORS: Record<EntityType, { bg: string; border: string; text: string; label: string }> = {
  Organization: { bg: '#1e3a8a', border: '#3b82f6', text: '#93c5fd', label: 'Org' },
  Domain: { bg: '#064e3b', border: '#10b981', text: '#6ee7b7', label: 'Domain' },
  Subdomain: { bg: '#047857', border: '#34d399', text: '#a7f3d0', label: 'Sub' },
  'IP address': { bg: '#78350f', border: '#f59e0b', text: '#fde68a', label: 'IP' },
  Email: { bg: '#581c87', border: '#a855f7', text: '#e9d5ff', label: 'Mail' },
  Person: { bg: '#312e81', border: '#6366f1', text: '#c7d2fe', label: 'Person' },
  URL: { bg: '#134e4a', border: '#14b8a6', text: '#99f6e4', label: 'URL' },
  Document: { bg: '#701a75', border: '#d946ef', text: '#f5d0fe', label: 'Doc' },
  Port: { bg: '#831843', border: '#ec4899', text: '#fbcfe8', label: 'Port' },
  Service: { bg: '#0c4a6e', border: '#0ea5e9', text: '#7dd3fc', label: 'Service' },
  Technology: { bg: '#3f3f46', border: '#71717a', text: '#e4e4e7', label: 'Tech' },
  Vulnerability: { bg: '#881337', border: '#f43f5e', text: '#fecdd3', label: 'Vuln' }
};

export const EntityGraph: React.FC<EntityGraphProps> = ({
  entities,
  relationships,
  evidenceList
}) => {
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);

  // Filter toggles
  const [enabledTypes, setEnabledTypes] = useState<Record<EntityType, boolean>>({
    Organization: true,
    Domain: true,
    Subdomain: true,
    'IP address': true,
    Email: true,
    Person: true,
    URL: true,
    Document: true,
    Port: true,
    Service: true,
    Technology: true,
    Vulnerability: true
  });

  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Pre-calculated deterministic node coordinates for clean cluster visualization
  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const width = 1000;
    const height = 650;
    const centerX = width / 2;
    const centerY = height / 2;

    // Cluster by Entity Type radially
    const total = entities.length;
    entities.forEach((entity, index) => {
      // Deterministic layout based on index and type
      let radius = 180;
      let angle = (index / Math.max(1, total)) * 2 * Math.PI;

      if (entity.type === 'Organization') {
        positions[entity.id] = { x: centerX, y: centerY - 120 };
      } else if (entity.type === 'Domain') {
        positions[entity.id] = { x: centerX, y: centerY };
      } else if (entity.type === 'Subdomain') {
        radius = 160;
        angle = ((index % 4) / 4) * Math.PI + Math.PI * 0.9;
        positions[entity.id] = {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius
        };
      } else if (entity.type === 'IP address') {
        positions[entity.id] = { x: centerX + 180, y: centerY + 40 };
      } else if (entity.type === 'Port' || entity.type === 'Service') {
        radius = 280;
        angle = Math.PI * 0.15 + (index % 3) * 0.4;
        positions[entity.id] = {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius
        };
      } else if (entity.type === 'Person' || entity.type === 'Email') {
        radius = 240;
        angle = Math.PI * 1.2 + (index % 4) * 0.35;
        positions[entity.id] = {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius
        };
      } else if (entity.type === 'Vulnerability') {
        positions[entity.id] = { x: centerX + 360, y: centerY + 180 };
      } else {
        radius = 220;
        angle = (index / total) * 2 * Math.PI;
        positions[entity.id] = {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius
        };
      }
    });

    return positions;
  }, [entities]);

  // Filtered lists
  const visibleEntities = useMemo(() => {
    return entities.filter(e => {
      if (!enabledTypes[e.type]) return false;
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return e.name.toLowerCase().includes(q) || e.primaryValue.toLowerCase().includes(q);
    });
  }, [entities, enabledTypes, searchQuery]);

  const visibleEntityIds = useMemo(() => {
    return new Set(visibleEntities.map(e => e.id));
  }, [visibleEntities]);

  const visibleRelationships = useMemo(() => {
    return relationships.filter(
      r => visibleEntityIds.has(r.sourceEntityId) && visibleEntityIds.has(r.targetEntityId)
    );
  }, [relationships, visibleEntityIds]);

  const selectedEntity = useMemo(() => {
    return entities.find(e => e.id === selectedEntityId) || null;
  }, [entities, selectedEntityId]);

  // Pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleExportJSON = () => {
    const payload = {
      exportTimestamp: new Date().toISOString(),
      nodes: visibleEntities,
      edges: visibleRelationships
    };
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(payload, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `footprintiq_graph_export_${Date.now()}.json`);
    dlAnchor.click();
  };

  return (
    <div className="relative flex h-[700px] w-full bg-slate-950 border border-slate-800 rounded-lg overflow-hidden select-none">
      {/* Main Canvas Viewport */}
      <div className="relative flex-1 h-full overflow-hidden flex flex-col">
        {/* Top Floating Control Bar */}
        <div className="absolute top-4 left-4 right-4 z-20 flex flex-wrap items-center justify-between gap-3 pointer-events-none">
          {/* Search Input */}
          <div className="relative pointer-events-auto flex items-center">
            <Search className="absolute left-2.5 w-3.5 h-3.5 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search graph nodes..."
              className="pl-8 pr-3 py-1.5 text-xs bg-slate-900/90 border border-slate-700/80 rounded-md text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-hidden w-56 shadow-lg backdrop-blur-xs"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 text-xs text-slate-400 hover:text-slate-200"
              >
                ×
              </button>
            )}
          </div>

          {/* Action Tools */}
          <div className="flex items-center gap-2 pointer-events-auto">
            {/* Filter Toggle */}
            <div className="relative">
              <button
                onClick={() => setIsFilterOpen(!isFilterOpen)}
                className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs bg-slate-900/90 border border-slate-700/80 rounded-md text-slate-200 hover:bg-slate-800 transition-colors shadow-lg backdrop-blur-xs"
              >
                <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
                <span>Entity Filters</span>
              </button>

              {isFilterOpen && (
                <div
                  className="absolute right-0 mt-2 w-64 p-3 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl z-40 space-y-2 text-xs"
                  onMouseLeave={() => setIsFilterOpen(false)}
                >
                  <div className="font-semibold text-slate-200 pb-1 border-b border-slate-800 flex justify-between items-center">
                    <span>Toggle Entity Types</span>
                    <button
                      onClick={() => {
                        const allOn = Object.keys(enabledTypes).reduce((acc, k) => {
                          acc[k as EntityType] = true;
                          return acc;
                        }, {} as Record<EntityType, boolean>);
                        setEnabledTypes(allOn);
                      }}
                      className="text-[10px] text-cyan-400 hover:underline"
                    >
                      Show All
                    </button>
                  </div>
                  <div className="max-h-60 overflow-y-auto space-y-1.5">
                    {(Object.keys(ENTITY_COLORS) as EntityType[]).map(type => (
                      <label
                        key={type}
                        className="flex items-center gap-2 text-slate-300 hover:text-white cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={enabledTypes[type]}
                          onChange={e =>
                            setEnabledTypes({
                              ...enabledTypes,
                              [type]: e.target.checked
                            })
                          }
                          className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-0"
                        />
                        <span
                          className="w-2.5 h-2.5 rounded-full"
                          style={{ backgroundColor: ENTITY_COLORS[type].border }}
                        />
                        <span className="truncate">{type}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Zoom Controls */}
            <div className="flex items-center bg-slate-900/90 border border-slate-700/80 rounded-md shadow-lg overflow-hidden backdrop-blur-xs">
              <button
                onClick={() => setZoom(z => Math.min(2.5, z + 0.15))}
                className="p-1.5 text-slate-300 hover:text-cyan-300 hover:bg-slate-800 transition-colors"
                title="Zoom In"
                aria-label="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setZoom(z => Math.max(0.4, z - 0.15))}
                className="p-1.5 text-slate-300 hover:text-cyan-300 hover:bg-slate-800 transition-colors"
                title="Zoom Out"
                aria-label="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => {
                  setZoom(1);
                  setPan({ x: 0, y: 0 });
                }}
                className="p-1.5 text-slate-300 hover:text-cyan-300 hover:bg-slate-800 transition-colors border-l border-slate-800"
                title="Reset View"
                aria-label="Reset View"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Export Payload */}
            <button
              onClick={handleExportJSON}
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs bg-slate-900/90 border border-slate-700/80 rounded-md text-slate-200 hover:bg-slate-800 transition-colors shadow-lg backdrop-blur-xs"
              title="Export Graph JSON"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden sm:inline">Export</span>
            </button>
          </div>
        </div>

        {/* Interactive SVG Canvas */}
        <div
          className={`flex-1 w-full h-full cursor-${isDragging ? 'grabbing' : 'grab'}`}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
        >
          <svg
            ref={svgRef}
            className="w-full h-full"
            viewBox="0 0 1000 650"
            preserveAspectRatio="xMidYMid meet"
          >
            <defs>
              <marker
                id="arrowhead"
                markerWidth="8"
                markerHeight="6"
                refX="18"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#475569" />
              </marker>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" />
              </pattern>
            </defs>

            {/* Background Grid */}
            <rect width="100%" height="100%" fill="url(#grid)" />

            <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
              {/* Edges / Relationships */}
              {visibleRelationships.map(rel => {
                const srcPos = nodePositions[rel.sourceEntityId];
                const tgtPos = nodePositions[rel.targetEntityId];
                if (!srcPos || !tgtPos) return null;

                const isEdgeHighlighted =
                  selectedEntityId === rel.sourceEntityId || selectedEntityId === rel.targetEntityId;

                // Curved bezier path
                const dx = tgtPos.x - srcPos.x;
                const dy = tgtPos.y - srcPos.y;
                const midX = (srcPos.x + tgtPos.x) / 2 - dy * 0.15;
                const midY = (srcPos.y + tgtPos.y) / 2 + dx * 0.15;

                return (
                  <g key={rel.id} className="transition-all">
                    <path
                      d={`M ${srcPos.x} ${srcPos.y} Q ${midX} ${midY} ${tgtPos.x} ${tgtPos.y}`}
                      fill="none"
                      stroke={isEdgeHighlighted ? '#38bdf8' : '#334155'}
                      strokeWidth={isEdgeHighlighted ? 2.5 : 1.2}
                      strokeDasharray={rel.type === 'associated_with' ? '4 3' : undefined}
                      markerEnd="url(#arrowhead)"
                      opacity={0.8}
                    />
                    <text
                      x={midX}
                      y={midY}
                      fill={isEdgeHighlighted ? '#7dd3fc' : '#64748b'}
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="pointer-events-none select-none"
                    >
                      {rel.type}
                    </text>
                  </g>
                );
              })}

              {/* Entity Nodes */}
              {visibleEntities.map(node => {
                const pos = nodePositions[node.id] || { x: 500, y: 325 };
                const isSelected = selectedEntityId === node.id;
                const colors = ENTITY_COLORS[node.type] || ENTITY_COLORS.Technology;

                return (
                  <g
                    key={node.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onClick={e => {
                      e.stopPropagation();
                      setSelectedEntityId(node.id);
                    }}
                    className="cursor-pointer group"
                  >
                    {/* Pulsing ring on selected */}
                    {isSelected && (
                      <circle
                        r="24"
                        fill="none"
                        stroke="#38bdf8"
                        strokeWidth="2"
                        className="animate-pulse"
                      />
                    )}

                    {/* Node circle */}
                    <circle
                      r="16"
                      fill={colors.bg}
                      stroke={isSelected ? '#38bdf8' : colors.border}
                      strokeWidth={isSelected ? 3 : 1.8}
                      className="transition-transform group-hover:scale-110 shadow-lg"
                    />

                    {/* Short Type glyph / initials */}
                    <text
                      y="4"
                      fill={colors.text}
                      fontSize="9"
                      fontFamily="monospace"
                      fontWeight="bold"
                      textAnchor="middle"
                      className="pointer-events-none"
                    >
                      {colors.label.slice(0, 3)}
                    </text>

                    {/* Node primary label */}
                    <text
                      y="28"
                      fill="#f1f5f9"
                      fontSize="11"
                      fontWeight="500"
                      textAnchor="middle"
                      className="pointer-events-none drop-shadow-md"
                    >
                      {node.name.length > 20 ? `${node.name.slice(0, 18)}...` : node.name}
                    </text>

                    {/* Node subtitle */}
                    <text
                      y="39"
                      fill="#94a3b8"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="pointer-events-none"
                    >
                      {node.type}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        {/* Bottom Legend */}
        <div className="p-2.5 bg-slate-950/80 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs z-10">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-[11px] text-slate-400 font-medium uppercase tracking-wider">Legend:</span>
            {[
              { type: 'Organization', color: ENTITY_COLORS.Organization.border },
              { type: 'Domain', color: ENTITY_COLORS.Domain.border },
              { type: 'IP address', color: ENTITY_COLORS['IP address'].border },
              { type: 'Person', color: ENTITY_COLORS.Person.border },
              { type: 'Port', color: ENTITY_COLORS.Port.border },
              { type: 'Vulnerability', color: ENTITY_COLORS.Vulnerability.border }
            ].map(item => (
              <span key={item.type} className="flex items-center gap-1.5 text-[11px] text-slate-300">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                <span>{item.type}</span>
              </span>
            ))}
          </div>

          <div className="text-[11px] text-slate-400 font-mono">
            Showing <strong className="text-slate-200">{visibleEntities.length}</strong> nodes ·{' '}
            <strong className="text-slate-200">{visibleRelationships.length}</strong> relationships
          </div>
        </div>
      </div>

      {/* Node Detail Drawer on selection */}
      {selectedEntity && (
        <NodeDetailDrawer
          entity={selectedEntity}
          relationships={relationships}
          allEntities={entities}
          evidenceList={evidenceList}
          onClose={() => setSelectedEntityId(null)}
          onSelectEntity={id => setSelectedEntityId(id)}
        />
      )}
    </div>
  );
};
