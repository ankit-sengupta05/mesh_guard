import React from 'react';

/** Animated shimmer block for content loading states */
const Shimmer: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div
    className={`animate-pulse bg-gray-800 rounded ${className}`}
    style={{
      backgroundImage:
        'linear-gradient(90deg, #1f2937 25%, #374151 50%, #1f2937 75%)',
      backgroundSize: '200% 100%',
      animation: 'shimmer 1.6s infinite',
    }}
  />
);

export const MetricsBarSkeleton: React.FC = () => (
  <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
    {Array.from({ length: 5 }).map((_, i) => (
      <div key={i} className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
        <div className="flex justify-between">
          <Shimmer className="h-3 w-24" />
          <Shimmer className="h-4 w-4 rounded-full" />
        </div>
        <Shimmer className="h-8 w-16" />
        <Shimmer className="h-2 w-full" />
      </div>
    ))}
  </div>
);

export const ThreatFeedSkeleton: React.FC = () => (
  <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
    <div className="p-4 border-b border-gray-800 flex justify-between items-center">
      <Shimmer className="h-5 w-32" />
      <div className="flex space-x-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Shimmer key={i} className="h-6 w-14 rounded-full" />
        ))}
      </div>
    </div>
    <div className="p-2 space-y-2">
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} className="border border-gray-800 rounded p-3 flex items-center space-x-3">
          <Shimmer className="h-3 w-16" />
          <Shimmer className="h-4 w-20" />
          <Shimmer className="h-4 w-32" />
          <Shimmer className="h-3 flex-1" />
        </div>
      ))}
    </div>
  </div>
);

export const AgentGridSkeleton: React.FC = () => (
  <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
    <div className="flex justify-between items-center mb-4">
      <Shimmer className="h-5 w-32" />
      <Shimmer className="h-3 w-24" />
    </div>
    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-3">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="border border-gray-800 rounded-lg p-3 space-y-3">
          <div className="flex justify-between">
            <Shimmer className="h-4 w-28" />
            <Shimmer className="h-4 w-16 rounded-full" />
          </div>
          <Shimmer className="h-1.5 w-full rounded-full" />
          <Shimmer className="h-1.5 w-full rounded-full" />
          <div className="pt-2 border-t border-gray-800 flex justify-between">
            <Shimmer className="h-3 w-20" />
            <Shimmer className="h-3 w-12" />
          </div>
        </div>
      ))}
    </div>
  </div>
);
