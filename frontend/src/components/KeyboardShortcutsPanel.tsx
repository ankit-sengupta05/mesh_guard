import React, { useEffect } from 'react';
import { X, Keyboard } from 'lucide-react';

interface Shortcut {
  keys: string[];
  description: string;
}

const SHORTCUTS: Shortcut[] = [
  { keys: ['?'], description: 'Show/hide this panel' },
  { keys: ['1'], description: 'Go to Overview' },
  { keys: ['2'], description: 'Go to Trust Graph' },
  { keys: ['3'], description: 'Go to Threat Feed' },
  { keys: ['4'], description: 'Go to Attack Simulator' },
  { keys: ['5'], description: 'Go to Self-Healing' },
  { keys: ['E'], description: 'Export event log as JSON' },
  { keys: ['T'], description: 'Toggle dark / light mode' },
  { keys: ['Esc'], description: 'Close modal / panel' },
];

interface KeyboardShortcutsPanelProps {
  visible: boolean;
  onClose: () => void;
}

export const KeyboardShortcutsPanel: React.FC<KeyboardShortcutsPanelProps> = ({
  visible,
  onClose,
}) => {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  if (!visible) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <div className="flex items-center space-x-2 text-gray-200">
            <Keyboard size={18} className="text-blue-400" />
            <span className="font-semibold">Keyboard Shortcuts</span>
          </div>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Shortcuts list */}
        <div className="px-6 py-4 space-y-3">
          {SHORTCUTS.map((s, i) => (
            <div key={i} className="flex items-center justify-between">
              <span className="text-sm text-gray-400">{s.description}</span>
              <div className="flex space-x-1">
                {s.keys.map((k, ki) => (
                  <kbd
                    key={ki}
                    className="inline-flex items-center px-2 py-0.5 rounded border border-gray-700 bg-gray-800 text-gray-300 text-xs font-mono"
                  >
                    {k}
                  </kbd>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="px-6 py-3 border-t border-gray-800 text-xs text-gray-600 text-center">
          Press <kbd className="px-1.5 py-0.5 rounded border border-gray-700 bg-gray-800 font-mono">?</kbd> anytime to toggle
        </div>
      </div>
    </div>
  );
};
