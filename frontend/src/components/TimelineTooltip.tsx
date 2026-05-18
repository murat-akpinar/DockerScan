import React from 'react';
import type { TooltipProps } from 'recharts';

// Custom tooltip for the unified timeline charts:
// shows only series that have numeric value at the hovered point.
const TimelineTooltip: React.FC<TooltipProps<number, string>> = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null;

  const visible = payload.filter((item) => typeof item.value === 'number');
  if (!visible.length) return null;

  return (
    <div
      style={{
        backgroundColor: '#1e1e2e',
        border: '1px solid #313244',
        borderRadius: 8,
        padding: '8px 12px',
        boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
        pointerEvents: 'none',
      }}
    >
      <div style={{ fontSize: 12, marginBottom: 4, color: '#cdd6f4' }}>{label}</div>
      {visible.map((item) => (
        <div
          key={String(item.dataKey)}
          style={{ fontSize: 12, color: (item.color as string) || '#cdd6f4' }}
        >
          <span>{item.name}</span>
          {': '}
          <strong>{item.value}</strong>
          <span> açık</span>
        </div>
      ))}
    </div>
  );
};

export default React.memo(TimelineTooltip);


