import React from 'react';
import type { TooltipProps } from 'recharts';

// Custom tooltip for the unified timeline charts:
// shows only series that have numeric value at the hovered point.
const TimelineTooltip: React.FC<TooltipProps<number, string>> = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null;

  // En yüksek değer en üstte olacak şekilde sırala; üst üste binen noktalarda okumayı kolaylaştırır.
  const visible = payload
    .filter((item) => typeof item.value === 'number')
    .sort((a, b) => (b.value as number) - (a.value as number));
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
        maxWidth: 280,
      }}
    >
      <div style={{ fontSize: 12, marginBottom: 6, color: '#cdd6f4' }}>{label}</div>
      {visible.map((item) => (
        <div
          key={String(item.dataKey)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 12,
            color: '#cdd6f4',
            lineHeight: 1.6,
          }}
        >
          <span
            style={{
              width: 9,
              height: 9,
              borderRadius: 2,
              backgroundColor: (item.color as string) || '#cdd6f4',
              flexShrink: 0,
            }}
          />
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {item.name}
          </span>
          <strong style={{ marginLeft: 'auto', paddingLeft: 12 }}>
            {item.value}
            <span style={{ fontWeight: 400, color: '#9399b2' }}> açık</span>
          </strong>
        </div>
      ))}
    </div>
  );
};

export default React.memo(TimelineTooltip);


